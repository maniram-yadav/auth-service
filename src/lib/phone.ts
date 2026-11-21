import { getCountries, parsePhoneNumberFromString, type CountryCode } from 'libphonenumber-js';

const COUNTRIES = new Set<string>(getCountries());

export const isCountryCode = (value: string): value is CountryCode => COUNTRIES.has(value);

/**
 * Normalizes a phone number to E.164 (e.g. "+14155550123").
 * Accepts international format ("+1 415…") or a national number with [country].
 * Returns null when the number is not valid.
 */
export function toE164(phone: string, country?: string): string | null {
  const defaultCountry = country && isCountryCode(country) ? country : undefined;
  const parsed = parsePhoneNumberFromString(phone.trim(), defaultCountry);
  if (!parsed || !parsed.isValid()) return null;
  return parsed.number;
}

/** "+1•••••••0123" – used in logs so full numbers are never written. */
export const maskPhone = (e164: string): string =>
  e164.length <= 6 ? '•••' : `${e164.slice(0, 2)}${'•'.repeat(e164.length - 6)}${e164.slice(-4)}`;

export const maskEmail = (email: string): string => {
  const [local = '', domain = ''] = email.split('@');
  return `${local.slice(0, 1)}***@${domain}`;
};
