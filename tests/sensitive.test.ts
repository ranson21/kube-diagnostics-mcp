import { describe, expect, it } from "vitest";
import { luhnValid, scanForSensitiveData } from "../src/security/sensitive.js";

describe("scanForSensitiveData", () => {
  it("finds emails, luhn-valid cards, ssn, jwt and masks samples", () => {
    const lines = [
      "user jane.doe@example.com placed order",
      "card 4111 1111 1111 1111 charged",
      "card 1234 5678 9012 3456 is not luhn valid",
      "ssn 123-45-6789",
      "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
      "nothing here 2026-09-16T10:00:00Z 200 12ms",
    ];
    const f = scanForSensitiveData(lines);
    const kinds = Object.fromEntries(f.map((x) => [x.kind, x]));
    expect(kinds.email.count).toBe(1);
    expect(kinds.email.sample).toBe("ja***@***.com");
    expect(kinds.credit_card.count).toBe(1);
    expect(kinds.credit_card.sample).toBe("41** **** **** 11");
    expect(kinds.credit_card.locations).toEqual([2]);
    expect(kinds.us_ssn.sample).toBe("***-**-****");
    expect(kinds.jwt).toBeDefined();
    expect(JSON.stringify(f)).not.toContain("4111 1111");
    expect(JSON.stringify(f)).not.toContain("jane.doe@example.com");
  });
  it("luhn", () => {
    expect(luhnValid("4111111111111111")).toBe(true);
    expect(luhnValid("4111111111111112")).toBe(false);
  });
  it("ignores timestamps and ids as phone numbers", () => {
    const f = scanForSensitiveData(["2026-09-16 12:34:56 req 1234567890 took 555 ms"]);
    expect(f.find((x) => x.kind === "phone")).toBeUndefined();
  });
});
