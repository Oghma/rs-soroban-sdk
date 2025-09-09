#[cfg(not(target_family = "wasm"))]
use crate::xdr::ScVal;
use crate::{
    env::internal::{self, BytesObject, U256Val, U64Val},
    impl_bytesn_repr,
    unwrap::{UnwrapInfallible, UnwrapOptimized},
    Bytes, BytesN, ConversionError, Env, IntoVal, TryFromVal, Val, Vec, U256,
};
use core::{cmp::Ordering, fmt::Debug};

// BN254 (aka altbn128) serialization sizes (uncompressed)
pub const FP_SERIALIZED_SIZE: usize = 32;
pub const FP2_SERIALIZED_SIZE: usize = FP_SERIALIZED_SIZE * 2;
pub const G1_SERIALIZED_SIZE: usize = FP_SERIALIZED_SIZE * 2; // X || Y
pub const G2_SERIALIZED_SIZE: usize = FP2_SERIALIZED_SIZE * 2; // X(c1||c0) || Y(c1||c0)

pub struct Bn254 {
    env: Env,
}

#[derive(Clone)]
#[repr(transparent)]
pub struct G1Affine(BytesN<G1_SERIALIZED_SIZE>);

#[derive(Clone)]
#[repr(transparent)]
pub struct G2Affine(BytesN<G2_SERIALIZED_SIZE>);

#[derive(Clone)]
#[repr(transparent)]
pub struct Fp(BytesN<FP_SERIALIZED_SIZE>);

#[derive(Clone)]
#[repr(transparent)]
pub struct Fp2(BytesN<FP2_SERIALIZED_SIZE>);

#[derive(Clone)]
#[repr(transparent)]
pub struct Fr(U256);

impl_bytesn_repr!(G1Affine, G1_SERIALIZED_SIZE);
impl_bytesn_repr!(G2Affine, G2_SERIALIZED_SIZE);
impl_bytesn_repr!(Fp, FP_SERIALIZED_SIZE);
impl_bytesn_repr!(Fp2, FP2_SERIALIZED_SIZE);

impl Fr {
    pub fn env(&self) -> &Env {
        self.0.env()
    }
    pub fn from_u256(value: U256) -> Self {
        value.into()
    }
    pub fn to_u256(&self) -> U256 {
        self.0.clone()
    }
    pub fn as_u256(&self) -> &U256 {
        &self.0
    }
    pub fn from_bytes(bytes: BytesN<32>) -> Self {
        U256::from_be_bytes(bytes.env(), bytes.as_ref()).into()
    }
    pub fn to_bytes(&self) -> BytesN<32> {
        self.as_u256().to_be_bytes().try_into().unwrap_optimized()
    }
    pub fn as_val(&self) -> &Val {
        self.0.as_val()
    }
    pub fn to_val(&self) -> Val {
        self.0.to_val()
    }

    pub fn pow(&self, rhs: u64) -> Self {
        let env = self.env();
        let rhs = U64Val::try_from_val(env, &rhs).unwrap_optimized();
        let v = internal::Env::bn254_fr_pow(env, self.into(), rhs).unwrap_infallible();
        U256::try_from_val(env, &v).unwrap_infallible().into()
    }
    pub fn inv(&self) -> Self {
        let env = self.env();
        let v = internal::Env::bn254_fr_inv(env, self.into()).unwrap_infallible();
        U256::try_from_val(env, &v).unwrap_infallible().into()
    }
}

impl From<U256> for Fr {
    fn from(value: U256) -> Self {
        Self(value)
    }
}
impl From<&Fr> for U256Val {
    fn from(value: &Fr) -> Self {
        value.as_u256().into()
    }
}
impl TryFromVal<Env, Val> for Fr {
    type Error = ConversionError;
    fn try_from_val(env: &Env, val: &Val) -> Result<Self, Self::Error> {
        let u = U256::try_from_val(env, val)?;
        Ok(Fr(u))
    }
}
impl TryFromVal<Env, Fr> for Val {
    type Error = ConversionError;
    fn try_from_val(_env: &Env, fr: &Fr) -> Result<Self, Self::Error> {
        Ok(fr.to_val())
    }
}
impl TryFromVal<Env, &Fr> for Val {
    type Error = ConversionError;
    fn try_from_val(_env: &Env, fr: &&Fr) -> Result<Self, Self::Error> {
        Ok(fr.to_val())
    }
}

impl Bn254 {
    pub(crate) fn new(env: &Env) -> Bn254 {
        Bn254 { env: env.clone() }
    }
    pub fn env(&self) -> &Env {
        &self.env
    }

    // g1
    pub fn g1_is_in_subgroup(&self, p: &G1Affine) -> bool {
        let env = self.env();
        let res =
            internal::Env::bn254_check_g1_is_in_subgroup(env, p.to_object()).unwrap_infallible();
        res.into()
    }
    pub fn g1_add(&self, p0: &G1Affine, p1: &G1Affine) -> G1Affine {
        let env = self.env();
        let bin =
            internal::Env::bn254_g1_add(env, p0.to_object(), p1.to_object()).unwrap_infallible();
        unsafe { G1Affine::from_bytes(BytesN::unchecked_new(env.clone(), bin)) }
    }
    pub fn g1_mul(&self, p0: &G1Affine, scalar: &Fr) -> G1Affine {
        let env = self.env();
        let bin =
            internal::Env::bn254_g1_mul(env, p0.to_object(), scalar.into()).unwrap_infallible();
        unsafe { G1Affine::from_bytes(BytesN::unchecked_new(env.clone(), bin)) }
    }

    // g2
    pub fn g2_is_in_subgroup(&self, p: &G2Affine) -> bool {
        let env = self.env();
        let res =
            internal::Env::bn254_check_g2_is_in_subgroup(env, p.to_object()).unwrap_infallible();
        res.into()
    }
    pub fn g2_add(&self, p0: &G2Affine, p1: &G2Affine) -> G2Affine {
        let env = self.env();
        let bin =
            internal::Env::bn254_g2_add(env, p0.to_object(), p1.to_object()).unwrap_infallible();
        unsafe { G2Affine::from_bytes(BytesN::unchecked_new(env.clone(), bin)) }
    }
    pub fn g2_mul(&self, p0: &G2Affine, scalar: &Fr) -> G2Affine {
        let env = self.env();
        let bin =
            internal::Env::bn254_g2_mul(env, p0.to_object(), scalar.into()).unwrap_infallible();
        unsafe { G2Affine::from_bytes(BytesN::unchecked_new(env.clone(), bin)) }
    }

    // pairing
    pub fn pairing_check(&self, vp1: Vec<G1Affine>, vp2: Vec<G2Affine>) -> bool {
        let env = self.env();
        internal::Env::bn254_multi_pairing_check(env, vp1.into(), vp2.into())
            .unwrap_infallible()
            .into()
    }

    // scalar arithmetic
    pub fn fr_add(&self, lhs: &Fr, rhs: &Fr) -> Fr {
        let env = self.env();
        let v = internal::Env::bn254_fr_add(env, lhs.into(), rhs.into()).unwrap_infallible();
        U256::try_from_val(env, &v).unwrap_infallible().into()
    }
    pub fn fr_sub(&self, lhs: &Fr, rhs: &Fr) -> Fr {
        let env = self.env();
        let v = internal::Env::bn254_fr_sub(env, lhs.into(), rhs.into()).unwrap_infallible();
        U256::try_from_val(env, &v).unwrap_infallible().into()
    }
    pub fn fr_mul(&self, lhs: &Fr, rhs: &Fr) -> Fr {
        let env = self.env();
        let v = internal::Env::bn254_fr_mul(env, lhs.into(), rhs.into()).unwrap_infallible();
        U256::try_from_val(env, &v).unwrap_infallible().into()
    }
}
