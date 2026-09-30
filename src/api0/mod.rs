// src/api0/mod.rs
//
// The bridge between an api0 account and a wallet.
//
// api0 knows people by email; solanize knows them by wallet address. Neither
// concept belongs in the other system — api0 stays agnostic about Solana, and
// solanize does not become an identity provider — so the mapping lives here,
// owned by the side that understands what a wallet is.
pub mod guards;
pub mod handlers;
