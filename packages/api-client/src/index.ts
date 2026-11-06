// T-34 P-53 T-35
import createClient from "openapi-fetch";
import type { Client, Middleware } from "openapi-fetch";

import type { components, operations, paths } from "./generated/work-v1.js";

export type { components, operations, paths };

/** A schema of the Work API, by its name in the OpenAPI document. */
export type Schema<Name extends keyof components["schemas"]> = components["schemas"][Name];

/** The Work API client: every path, method, parameter, body and answer as `sdks/openapi/work-v1.json` states it. */
export type WorkClient = Client<paths>;

/** The proof of one request for its caller: the Access access token and its DPoP proof over the request (RFC 9449). */
export interface CallerProof {
  readonly token: string;
  readonly dpop: string;
}

/** Proves `request` for the caller; the client asks once per request and never keeps the answer. */
export type Prover = (request: Request) => Promise<CallerProof>;

/** Where the Work API is and, for the operations that act for a caller, how a request is proven. */
export interface WorkClientOptions {
  readonly baseUrl: string;
  readonly prove?: Prover;
}

/** A client of the Work API at `baseUrl`; with `prove`, every request carries `Authorization: DPoP` and its `DPoP` proof. */
export function createWorkClient(options: WorkClientOptions): WorkClient {
  const client = createClient<paths>({ baseUrl: options.baseUrl });
  const prove = options.prove;
  if (prove !== undefined) {
    const proving: Middleware = {
      async onRequest({ request }) {
        const proof = await prove(request);
        request.headers.set("authorization", `DPoP ${proof.token}`);
        request.headers.set("dpop", proof.dpop);
        return request;
      },
    };
    client.use(proving);
  }
  return client;
}
