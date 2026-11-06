import { createServer } from "node:http";
import type { IncomingHttpHeaders, Server } from "node:http";
import type { AddressInfo } from "node:net";

import { afterAll, beforeAll, describe, expect, expectTypeOf, it } from "vitest";

import { createWorkClient } from "./index.js";
import type { Schema } from "./index.js";

interface Seen {
  readonly method: string;
  readonly url: string;
  readonly headers: IncomingHttpHeaders;
}

const LEDGER = "led_0101010101010101010101010101010101010101010101010101010101010101";
const WORK = "wrk_0202020202020202020202020202020202020202020202020202020202020202";

const work: Schema<"WorkAnswer"> = {
  ledger: LEDGER,
  work: WORK,
  version: "7",
  first_pos: "1",
  last_pos: "7",
  opened_at: "2026-11-06T12:00:00Z",
  updated_at: "2026-11-06T12:05:00Z",
  position: "pos_AQ",
};

const problem: Schema<"ProblemType"> = {
  type: "https://suiss.app/ns/work/problems/busy",
  code: "busy",
  title: "Busy",
  status: 503,
  retryable: true,
};

const seen: Seen[] = [];
let server: Server;
let baseUrl = "";

beforeAll(async () => {
  server = createServer((request, response) => {
    seen.push({ method: request.method ?? "", url: request.url ?? "", headers: request.headers });
    const body = request.url?.startsWith("/v1/problems/") === true ? problem : work;
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify(body));
  });
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });
  baseUrl = `http://127.0.0.1:${String((server.address() as AddressInfo).port)}`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error === undefined) {
        resolve();
      } else {
        reject(error);
      }
    });
  });
});

describe("createWorkClient", () => {
  // T-34
  it("t_34 reads a public operation typed as the OpenAPI document states it", async () => {
    const client = createWorkClient({ baseUrl });
    const { data, error } = await client.GET("/v1/problems/{code}", {
      params: { path: { code: "busy" } },
    });
    expect(error).toBeUndefined();
    expect(data).toEqual(problem);
    expectTypeOf(data).toEqualTypeOf<Schema<"ProblemType"> | undefined>();
    expect(seen.at(-1)?.url).toBe("/v1/problems/busy");
    expect(seen.at(-1)?.headers.authorization).toBeUndefined();
  });

  // T-34
  it("t_34 proves every request that acts for a caller with its DPoP token and proof", async () => {
    const proven: string[] = [];
    const client = createWorkClient({
      baseUrl,
      prove: (request) => {
        proven.push(`${request.method} ${request.url}`);
        return Promise.resolve({ token: "token-1", dpop: "proof-1" });
      },
    });
    const { data } = await client.GET("/v1/ledgers/{ledger}/works/{work}", {
      params: { path: { ledger: LEDGER, work: WORK } },
    });
    expect(data).toEqual(work);
    expectTypeOf(data).toEqualTypeOf<Schema<"WorkAnswer"> | undefined>();
    const last = seen.at(-1);
    expect(last?.method).toBe("GET");
    expect(last?.url).toBe(`/v1/ledgers/${LEDGER}/works/${WORK}`);
    expect(last?.headers.authorization).toBe("DPoP token-1");
    expect(last?.headers["dpop"]).toBe("proof-1");
    expect(proven).toEqual([`GET ${baseUrl}/v1/ledgers/${LEDGER}/works/${WORK}`]);
  });

  // T-34
  it("t_34 keeps 64-bit positions as strings", () => {
    expectTypeOf<Schema<"WorkAnswer">["first_pos"]>().toEqualTypeOf<string>();
    expectTypeOf<Schema<"ProblemType">["code"]>().toEqualTypeOf<Schema<"ProblemCode">>();
  });
});
