
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
struct Tree {
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
    fn attach(&mut self, left: bool, child: Tree) -> Result<()> {
        if self.child(left).is_some() {
            bail!("Tried to attach to left child, but it is already Some");
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
    type Item = Result<Op>;

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