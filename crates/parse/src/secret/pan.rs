//! Primary account numbers (PAN, SEC-24): a matched digit run counts only when, without its space or hyphen separators, it has the prefix and length of a payment brand and passes the Luhn check.

fn prefix(digits: &[u8], n: usize) -> Option<u32> {
    digits.get(..n)?.iter().try_fold(0u32, |acc, d| {
        acc.checked_mul(10)?
            .checked_add(u32::from(d.checked_sub(b'0')?))
    })
}

fn starts_in(digits: &[u8], n: usize, lo: u32, hi: u32) -> bool {
    prefix(digits, n).is_some_and(|v| (lo..=hi).contains(&v))
}

fn brand(digits: &[u8]) -> bool {
    let len = digits.len();
    let s = |n, lo, hi| starts_in(digits, n, lo, hi);
    let visa = s(1, 4, 4) && matches!(len, 13 | 16 | 19);
    let master = (s(2, 51, 55) || s(4, 2221, 2720)) && len == 16;
    let amex = (s(2, 34, 34) || s(2, 37, 37)) && len == 15;
    let discover = (s(4, 6011, 6011) || s(3, 644, 649) || s(2, 65, 65)) && (16..=19).contains(&len);
    let jcb = s(4, 3528, 3589) && (16..=19).contains(&len);
    let diners = (s(3, 300, 305) || s(2, 36, 36) || s(2, 38, 39)) && (14..=19).contains(&len);
    let unionpay = s(2, 62, 62) && (16..=19).contains(&len);
    visa || master || amex || discover || jcb || diners || unionpay
}

pub(super) fn luhn(digits: &[u8]) -> bool {
    let sum = digits
        .iter()
        .rev()
        .enumerate()
        .try_fold(0u32, |acc, (i, d)| {
            let v = u32::from(d.checked_sub(b'0')?);
            let v = if i.is_multiple_of(2) {
                v
            } else {
                let doubled = v.checked_mul(2)?;
                if doubled > 9 {
                    doubled.checked_sub(9)?
                } else {
                    doubled
                }
            };
            acc.checked_add(v)
        });
    sum.is_some_and(|s| s.is_multiple_of(10))
}

/// Whether `candidate` (digits with optional space or hyphen separators) is a primary account number.
pub(super) fn is_pan(candidate: &[u8]) -> bool {
    let digits: Vec<u8> = candidate
        .iter()
        .copied()
        .filter(|b| *b != b' ' && *b != b'-')
        .collect();
    digits.iter().all(u8::is_ascii_digit) && brand(&digits) && luhn(&digits)
}
