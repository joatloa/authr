pub trait AuthDatabase:
    UsersStore + SesssionsStore + AccountsStore + VerificationStore + Send + Sync
{
}

pub trait UsersStore {}
pub trait SesssionsStore {}
pub trait AccountsStore {}
pub trait VerificationStore {}
