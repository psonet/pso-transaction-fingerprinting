use chrono::{DateTime, Utc};
use derive_builder::Builder;
use fixed_num::Dec19x19;
use fixed_num_helper::FRAC_SCALE_I128;

pub mod currencies {
    pub use iso4217_static::*;
}

// Amount with currency representation
#[derive(Builder, Debug, Clone, PartialEq)]
#[builder(setter(into))]
pub struct Money {
    pub amount_base: u64,
    pub amount_atto: u64,
    pub currency: currencies::Currency,
}

impl Default for Money {
    fn default() -> Self {
        Money {
            amount_base: 0,
            amount_atto: 0,
            currency: currencies::Currency::Afghani,
        }
    }
}

// Raw Transaction representation
#[derive(Default, Builder, Debug, Clone, PartialEq)]
#[builder(setter(into))]
pub struct RawTransaction {
    pub bic: String,
    pub amount: Money,
    pub date_time: DateTime<Utc>,
}

impl TryFrom<(Dec19x19, &str)> for Money {
    type Error = anyhow::Error;

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn try_from(value: (Dec19x19, &str)) -> Result<Self, Self::Error> {
        let amount = value.0;
        let currency = currencies::Currency::try_from(value.1).map_err(|_| {
            anyhow::anyhow!(
                "Provided invalid currency code: {}, expected ISO 4217 code",
                value.1
            )
        })?;

        Ok(Money {
            amount_base: (amount.repr / FRAC_SCALE_I128) as u64,
            amount_atto: (amount.repr % FRAC_SCALE_I128) as u64 / 10,
            currency,
        })
    }
}

impl TryFrom<(i32, &str)> for Money {
    type Error = anyhow::Error;

    fn try_from(value: (i32, &str)) -> Result<Self, Self::Error> {
        let currency = currencies::Currency::try_from(value.1).map_err(|_| {
            anyhow::anyhow!(
                "Provided invalid currency code: {}, expected ISO 4217 code",
                value.1
            )
        })?;

        Ok(Money {
            amount_base: u64::from(value.0.unsigned_abs()),
            amount_atto: 0,
            currency,
        })
    }
}
impl TryFrom<(u32, &str)> for Money {
    type Error = anyhow::Error;

    fn try_from(value: (u32, &str)) -> Result<Self, Self::Error> {
        let currency = currencies::Currency::try_from(value.1).map_err(|_| {
            anyhow::anyhow!(
                "Provided invalid currency code: {}, expected ISO 4217 code",
                value.1
            )
        })?;

        Ok(Money {
            amount_base: u64::from(value.0),
            amount_atto: 0,
            currency,
        })
    }
}
impl TryFrom<(i64, &str)> for Money {
    type Error = anyhow::Error;

    fn try_from(value: (i64, &str)) -> Result<Self, Self::Error> {
        let currency = currencies::Currency::try_from(value.1).map_err(|_| {
            anyhow::anyhow!(
                "Provided invalid currency code: {}, expected ISO 4217 code",
                value.1
            )
        })?;

        Ok(Money {
            amount_base: value.0.unsigned_abs(),
            amount_atto: 0,
            currency,
        })
    }
}
impl TryFrom<(u64, &str)> for Money {
    type Error = anyhow::Error;

    fn try_from(value: (u64, &str)) -> Result<Self, Self::Error> {
        let currency = currencies::Currency::try_from(value.1).map_err(|_| {
            anyhow::anyhow!(
                "Provided invalid currency code: {}, expected ISO 4217 code",
                value.1
            )
        })?;

        Ok(Money {
            amount_base: value.0,
            amount_atto: 0,
            currency,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_money_from() {
        let currency = currencies::Currency::try_from("USD").unwrap();

        let money_1 = MoneyBuilder::default()
            .amount_base(1000u32)
            .amount_atto(554325 * 10u64.pow(12)) // .5
            .currency(currency)
            .build()
            .unwrap();

        let money_2: Money = (Dec19x19!(1000.554325), "132").try_into().unwrap();

        println!("Builder money:{:?}", money_1);
        println!("Converted money:{:?}", money_2);

        assert_eq!(money_1, money_2);
    }
}
