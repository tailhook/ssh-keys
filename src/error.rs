quick_error! {
    /// Key parsing error
    #[derive(Debug)]
    pub enum Error {
        /// This error usually means that file is damaged
        InvalidFormat {
            description("invalid key format")
        }
        /// Unsupported key type
        UnsupportedType(typ: String) {
            description("unsupported key type")
            display("unsupported key type {:?}", typ)
        }
        #[doc(hidden)]
        __Nonexhaustive
    }
}
