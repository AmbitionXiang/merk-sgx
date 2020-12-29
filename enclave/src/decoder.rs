use std::boxed::Box;
use std::vec::Vec;
use crate::hash::{kv_hash, node_hash, Hash, HASH_LENGTH, NULL_HASH};

#[derive(Debug, PartialEq)]
pub enum Op {
    /// Pushes a node on the stack.
    Push(Node),

    /// Pops the top stack item as `parent`. Pops the next top stack item as
    /// `child`. Attaches `child` as the left child of `parent`. Pushes the
    /// updated `parent` back on the stack.
    Parent,

    /// Pops the top stack item as `child`. Pops the next top stack item as
    /// `parent`. Attaches `child` as the right child of `parent`. Pushes the
    /// updated `parent` back on the stack.
    Child
}

/// A binary tree data structure used to represent a select subset of a tree
/// when verifying Merkle proofs.
pub struct Tree {
    node: Node,
    left: Option<Box<Tree>>,
    right: Option<Box<Tree>>
}

impl From<Node> for Tree {
    fn from(node: Node) -> Self {
        Tree { node, left: None, right: None }
    }
}

impl Tree {
    /// Returns an immutable reference to the child on the given side, if any.
    fn child(&self, left: bool) -> Option<&Tree> {
        if left {
            self.left.as_ref().map(|c| c.as_ref())
        } else {
            self.right.as_ref().map(|c| c.as_ref())
        }
    }

    /// Returns a mutable reference to the child on the given side, if any.
    fn child_mut(&mut self, left: bool) -> &mut Option<Box<Tree>> {
        if left {
            &mut self.left
        } else {
            &mut self.right
        }
    }

    /// Attaches the child to the `Tree`'s given side, and calculates its hash.
    /// Panics if there is already a child attached to this side.
    fn attach(&mut self, left: bool, child: Tree) -> Result<(), &'static str> {
        if self.child(left).is_some() {
            return Err("Tried to attach to left child, but it is already Some");
        }

        let child = child.into_hash();
        let boxed = Box::new(child);
        *self.child_mut(left) = Some(boxed);
        Ok(())
    }

    /// Gets the already-computed hash for this tree node. Panics if the hash
    /// has not already been calculated.
    #[inline]
    fn hash(&self) -> Hash {
        match self.node {
            Node::Hash(hash) => hash,
            _ => unreachable!("Expected Node::Hash")
        }
    }

    /// Returns the already-computed hash for this tree node's child on the
    /// given side, if any. If there is no child, returns the null hash
    /// (zero-filled).
    #[inline]
    fn child_hash(&self, left: bool) -> Hash {
        self.child(left)
            .map_or(NULL_HASH, |c| c.hash())
    }

    /// Consumes the tree node, calculates its hash, and returns a `Node::Hash`
    /// variant.
    fn into_hash(self) -> Tree {
        fn to_hash_node(tree: &Tree, kv_hash: Hash) -> Node {
            let hash = node_hash(
                &kv_hash,
                &tree.child_hash(true),
                &tree.child_hash(false)
            );
            Node::Hash(hash)
        }

        match &self.node {
            Node::Hash(_) => self.node,
            Node::KVHash(kv_hash) => to_hash_node(&self, *kv_hash),
            Node::KV(key, value) => {
                let kv_hash = kv_hash(key.as_slice(), value.as_slice());
                to_hash_node(&self, kv_hash)
            }
        }.into()
    }
}

/// A selected piece of data about a single tree node, to be contained in a
/// `Push` operator in a proof.
#[derive(Clone, Debug, PartialEq)]
pub enum Node {
    /// Represents the hash of a tree node.
    Hash(Hash),

    /// Represents the hash of the key/value pair of a tree node.
    KVHash(Hash),

    /// Represents the key and value of a tree node.
    KV(Vec<u8>, Vec<u8>)
}


pub struct Decoder<'a> {
    offset: usize,
    bytes: &'a [u8]
}

impl<'a> Decoder<'a> {
    pub fn new(proof_bytes: &'a [u8]) -> Self {
        Decoder {
            offset: 0,
            bytes: proof_bytes
        }
    }
}

impl<'a> Iterator for Decoder<'a> {
    type Item = Result<Op, &'static str>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }

        Some((|| {
            let bytes = &self.bytes[self.offset..];
            let op = Op::decode(bytes)?;
            self.offset += op.encoding_length();
            Ok(op)
        })())
    }
}


pub fn verify_proof(
    bytes: &[u8],
    keys: &[Vec<u8>],
    expected_hash: Hash
) -> Result<Vec<Option<Vec<u8>>>, &'static str> {
    // TODO: enforce a maximum proof size

    let mut stack: Vec<Tree> = Vec::with_capacity(32);
    let mut output = Vec::with_capacity(keys.len());

    let mut key_index = 0;
    let mut last_push = None;

    fn try_pop(stack: &mut Vec<Tree>) -> Result<Tree, &'static str> {
        match stack.pop() {
            None => Err("Stack underflow"),
            Some(node) => Ok(node)
        }
    };

    for op in Decoder::new(bytes) {
        match op? {
            Op::Parent => {
                let (mut parent, child) = (
                    try_pop(&mut stack)?,
                    try_pop(&mut stack)?
                );
                parent.attach(true, child)?;
                stack.push(parent);
            },
            Op::Child => {
                let (child, mut parent) = (
                    try_pop(&mut stack)?,
                    try_pop(&mut stack)?
                );
                parent.attach(false, child)?;
                stack.push(parent);
            },
            Op::Push(node) => {
                let node_clone = node.clone();
                let tree: Tree = node.into();
                stack.push(tree);

                if let Node::KV(key, value) = &node_clone {
                    // keys should always be increasing
                    if let Some(Node::KV(last_key, _)) = &last_push {
                        if key <= last_key {
                            return Err("Incorrect key ordering");
                        }
                    }

                    loop {
                        if key_index >= keys.len() || *key < keys[key_index] {
                            break;
                        } else if key == &keys[key_index] {
                            // KV for queried key
                            output.push(Some(value.clone()));
                        } else if *key > keys[key_index] {
                            match &last_push {
                                None | Some(Node::KV(_, _)) => {
                                    // previous push was a boundary (global edge or lower key),
                                    // so this is a valid absence proof
                                    output.push(None);
                                },
                                // proof is incorrect since it skipped queried keys
                                _ => return Err("Proof incorrectly formed"),
                            }
                        }

                        key_index += 1;
                    }
                }

                last_push = Some(node_clone);
            }
        }
    }

    // absence proofs for right edge
    if key_index < keys.len() {
        if let Some(Node::KV(_, _)) = last_push {
            for _ in 0..(keys.len() - key_index) {
                output.push(None);
            }
        } else {
            return Err("Proof incorrectly formed");
        }
    } else {
        debug_assert_eq!(keys.len(), output.len());
    }

    if stack.len() != 1 {
        return Err("Expected proof to result in exactly one stack item");
    }

    let root = stack.pop().unwrap();
    let hash = root.into_hash().hash();
    if hash != expected_hash {
        return Err(format!(
            "Proof did not match expected hash\n\tExpected: {:?}\n\tActual: {:?}",
            expected_hash, hash
        ).as_str());
    }

    Ok(output)
}