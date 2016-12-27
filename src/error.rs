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
        /// Private key was encrypted (we don't support encrypted keys yet)
        Encrypted {
            description("key was encrypted")
        }
        #[doc(hidden)]
        __Nonexhaustive
    }
}
