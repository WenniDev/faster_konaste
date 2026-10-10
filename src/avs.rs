use std::{
    ffi::{CStr, c_char, c_void},
    sync::OnceLock,
};

use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

use crate::Error;

pub type Node = *mut c_void;

pub const TYPE_S32: u32 = 6;
pub const TYPE_STR: u32 = 11;

const TRAVERSE_NEXT_SAME_NAME: u32 = 7;

type Proc = unsafe extern "system" fn() -> isize;
type PropertySearch = unsafe extern "C" fn(*mut c_void, Node, *const c_char) -> Node;
type PropertyNodeCreate =
    unsafe extern "C" fn(*mut c_void, Node, u32, *const c_char, *const c_char) -> Node;
type PropertyNodeRefer =
    unsafe extern "C" fn(*mut c_void, Node, *const c_char, u32, *mut c_void, u32) -> i32;
type PropertyNodeCommit = unsafe extern "C" fn(Node) -> i32;
type PropertyNodeClone = unsafe extern "C" fn(*mut c_void, Node, Node, bool) -> Node;
type PropertyNodeTraversal = unsafe extern "C" fn(Node, u32) -> Node;

pub struct Avs {
    property_search: PropertySearch,
    property_node_create: PropertyNodeCreate,
    property_node_refer: PropertyNodeRefer,
    /// Called by the updater on every node it creates, exact purpose unknown
    property_node_commit: PropertyNodeCommit,
    property_node_clone: PropertyNodeClone,
    property_node_traversal: PropertyNodeTraversal,
}

impl Avs {
    pub fn get() -> Result<&'static Avs, Error> {
        static AVS: OnceLock<Avs> = OnceLock::new();
        if let Some(avs) = AVS.get() {
            return Ok(avs);
        }
        let avs = Self::load()?;
        Ok(AVS.get_or_init(|| avs))
    }

    fn load() -> Result<Avs, Error> {
        unsafe {
            let module = GetModuleHandleA(c"avs2-core.dll".as_ptr() as *const u8);
            if module.is_null() {
                return Err(Error::MissingSymbol("avs2-core.dll"));
            }
            let ordinal = |ordinal: usize, name| {
                GetProcAddress(module, ordinal as *const u8).ok_or(Error::MissingSymbol(name))
            };

            Ok(Avs {
                property_search: std::mem::transmute::<Proc, PropertySearch>(ordinal(
                    162,
                    "property_search",
                )?),
                property_node_create: std::mem::transmute::<Proc, PropertyNodeCreate>(ordinal(
                    163,
                    "property_node_create",
                )?),
                property_node_refer: std::mem::transmute::<Proc, PropertyNodeRefer>(ordinal(
                    176,
                    "property_node_refer",
                )?),
                property_node_commit: std::mem::transmute::<Proc, PropertyNodeCommit>(ordinal(
                    171,
                    "property_node_commit",
                )?),
                property_node_clone: std::mem::transmute::<Proc, PropertyNodeClone>(ordinal(
                    165,
                    "property_node_clone",
                )?),
                property_node_traversal: std::mem::transmute::<Proc, PropertyNodeTraversal>(
                    ordinal(167, "property_node_traversal")?,
                ),
            })
        }
    }

    pub unsafe fn search(&self, property: *mut c_void, node: Node, path: &CStr) -> Option<Node> {
        let node = unsafe { (self.property_search)(property, node, path.as_ptr()) };
        (!node.is_null()).then_some(node)
    }

    /// Safety: `parent` must not be modified during the iteration
    pub unsafe fn children<'a>(
        &'a self,
        parent: Node,
        name: &CStr,
    ) -> impl Iterator<Item = Node> + 'a {
        let first = unsafe { self.search(std::ptr::null_mut(), parent, name) };
        std::iter::successors(first, move |node| {
            let next = unsafe { (self.property_node_traversal)(*node, TRAVERSE_NEXT_SAME_NAME) };
            (!next.is_null()).then_some(next)
        })
    }

    pub unsafe fn read_bytes(&self, node: Node, name: &CStr, capacity: usize) -> Vec<u8> {
        let mut buffer = vec![0u8; capacity];
        unsafe {
            (self.property_node_refer)(
                std::ptr::null_mut(),
                node,
                name.as_ptr(),
                TYPE_STR,
                buffer.as_mut_ptr() as *mut c_void,
                capacity as u32,
            );
        }
        let length = buffer
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(capacity);
        buffer.truncate(length);
        buffer
    }

    pub unsafe fn read_str(&self, node: Node, name: &CStr, capacity: usize) -> String {
        let bytes = unsafe { self.read_bytes(node, name, capacity) };
        String::from_utf8_lossy(&bytes).into_owned()
    }

    pub unsafe fn read_s32(&self, node: Node, name: &CStr) -> i32 {
        let mut value = 0i32;
        unsafe {
            (self.property_node_refer)(
                std::ptr::null_mut(),
                node,
                name.as_ptr(),
                TYPE_S32,
                &mut value as *mut i32 as *mut c_void,
                size_of::<i32>() as u32,
            );
        }
        value
    }

    /// Same create then commit sequence as the updater
    pub unsafe fn write_str(&self, node: Node, name: &CStr, value: &CStr) {
        unsafe {
            let child = (self.property_node_create)(
                std::ptr::null_mut(),
                node,
                TYPE_STR,
                name.as_ptr(),
                value.as_ptr(),
            );
            if !child.is_null() {
                (self.property_node_commit)(child);
            }
        }
    }

    /// Deep copies `node` under `parent`
    pub unsafe fn clone_node(&self, parent: Node, node: Node) {
        unsafe { (self.property_node_clone)(std::ptr::null_mut(), parent, node, true) };
    }
}
