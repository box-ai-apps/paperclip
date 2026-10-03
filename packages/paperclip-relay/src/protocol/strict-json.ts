/**
 * Minimal strict JSON parser that rejects duplicate object keys.
 *
 * `JSON.parse` silently keeps the *last* value for a duplicated key. On a
 * protocol shared between two independently released implementations that is
 * request smuggling: one side can validate `{"kind":"http","kind":"websocket"}`
 * as `http` while the other reads `websocket`, and each side behaves as though
 * it validated the same bytes. The relay must never make a decision on a frame
 * that was ambiguous to read, so duplicates are a hard error at any depth.
 *
 * This is intentionally small and only used for length-bounded control frames —
 * it is not a general-purpose JSON library. The identical parser is vendored
 * into the relay-server repository; `conformance/vectors.json` pins the cases
 * both implementations must agree on.
 */

/**
 * Raised only for a repeated object key, so the caller can distinguish
 * smuggling from ordinary syntax noise without string-matching messages.
 *
 * `JSON.parse` accepts both of these bodies without complaint, which is exactly
 * why the distinction matters: a duplicate key means the two implementations
 * disagreed about what the frame said.
 */
export class DuplicateJsonKeyError extends SyntaxError {
  readonly key: string;

  constructor(key: string) {
    super(`duplicate object key: ${JSON.stringify(key)}`);
    this.name = "DuplicateJsonKeyError";
    this.key = key;
  }
}

export function parseJsonNoDuplicateKeys(text: string): unknown {
  const parser = new StrictParser(text);
  const value = parser.parseValue();
  parser.skipWhitespace();
  if (!parser.atEnd()) {
    throw new SyntaxError("unexpected trailing content after JSON value");
  }
  return value;
}

class StrictParser {
  private pos = 0;
  constructor(private readonly src: string) {}

  atEnd(): boolean {
    return this.pos >= this.src.length;
  }

  skipWhitespace(): void {
    while (this.pos < this.src.length) {
      const ch = this.src[this.pos];
      if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") {
        this.pos += 1;
      } else {
        break;
      }
    }
  }

  parseValue(): unknown {
    this.skipWhitespace();
    if (this.atEnd()) throw new SyntaxError("unexpected end of input");
    const ch = this.src[this.pos];
    switch (ch) {
      case "{":
        return this.parseObject();
      case "[":
        return this.parseArray();
      case '"':
        return this.parseString();
      case "t":
        return this.parseBoolean();
      case "f":
        return this.parseBoolean();
      case "n":
        return this.parseNull();
      default:
        return this.parseNumber();
    }
  }

  private parseObject(): Record<string, unknown> {
    this.expect("{");
    const obj: Record<string, unknown> = {};
    const seen = new Set<string>();
    this.skipWhitespace();
    if (this.peek() === "}") {
      this.pos += 1;
      return obj;
    }
    for (;;) {
      this.skipWhitespace();
      if (this.peek() !== '"') throw new SyntaxError("expected object key string");
      const key = this.parseString();
      if (seen.has(key)) {
        throw new DuplicateJsonKeyError(key);
      }
      seen.add(key);
      this.skipWhitespace();
      this.expect(":");
      const value = this.parseValue();
      // defineProperty so a "__proto__" key cannot poison the prototype.
      Object.defineProperty(obj, key, {
        value,
        enumerable: true,
        writable: true,
        configurable: true,
      });
      this.skipWhitespace();
      const next = this.next();
      if (next === "}") return obj;
      if (next !== ",") throw new SyntaxError("expected , or } in object");
    }
  }

  private parseArray(): unknown[] {
    this.expect("[");
    const arr: unknown[] = [];
    this.skipWhitespace();
    if (this.peek() === "]") {
      this.pos += 1;
      return arr;
    }
    for (;;) {
      arr.push(this.parseValue());
      this.skipWhitespace();
      const next = this.next();
      if (next === "]") return arr;
      if (next !== ",") throw new SyntaxError("expected , or ] in array");
    }
  }

  private parseString(): string {
    this.expect('"');
    let out = "";
    for (;;) {
      if (this.atEnd()) throw new SyntaxError("unterminated string");
      const ch = this.src[this.pos++];
      if (ch === '"') return out;
      if (ch === "\\") {
        const esc = this.src[this.pos++];
        switch (esc) {
          case '"': out += '"'; break;
          case "\\": out += "\\"; break;
          case "/": out += "/"; break;
          case "b": out += "\b"; break;
          case "f": out += "\f"; break;
          case "n": out += "\n"; break;
          case "r": out += "\r"; break;
          case "t": out += "\t"; break;
          case "u": {
            const hex = this.src.slice(this.pos, this.pos + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new SyntaxError("bad unicode escape");
            out += String.fromCharCode(parseInt(hex, 16));
            this.pos += 4;
            break;
          }
          default:
            throw new SyntaxError("bad string escape");
        }
      } else {
        const code = ch.charCodeAt(0);
        if (code < 0x20) throw new SyntaxError("unescaped control character in string");
        out += ch;
      }
    }
  }

  private parseNumber(): number {
    const start = this.pos;
    const re = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
    re.lastIndex = this.pos;
    const match = re.exec(this.src);
    if (!match || match.index !== start) throw new SyntaxError("invalid number");
    this.pos += match[0].length;
    const num = Number(match[0]);
    if (!Number.isFinite(num)) throw new SyntaxError("non-finite number");
    return num;
  }

  private parseBoolean(): boolean {
    if (this.src.startsWith("true", this.pos)) {
      this.pos += 4;
      return true;
    }
    if (this.src.startsWith("false", this.pos)) {
      this.pos += 5;
      return false;
    }
    throw new SyntaxError("invalid literal");
  }

  private parseNull(): null {
    if (this.src.startsWith("null", this.pos)) {
      this.pos += 4;
      return null;
    }
    throw new SyntaxError("invalid literal");
  }

  private peek(): string {
    return this.src[this.pos];
  }

  private next(): string {
    return this.src[this.pos++];
  }

  private expect(ch: string): void {
    if (this.src[this.pos] !== ch) {
      throw new SyntaxError(`expected '${ch}'`);
    }
    this.pos += 1;
  }
}