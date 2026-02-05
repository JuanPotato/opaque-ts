// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { ctEqual } from './util.js'

import { scrypt } from '@noble/hashes/scrypt.js'
import { sha1 } from '@noble/hashes/legacy.js'
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js'
import { extract, expand } from '@noble/hashes/hkdf.js'
import { hmac } from '@noble/hashes/hmac.js'
import type { CHash } from '@noble/hashes/utils.js'

export interface PrngFn {
    random(numBytes: number): number[]
}

export class Prng implements PrngFn {
    random(numBytes: number): number[] {
        return Array.from(crypto.getRandomValues(new Uint8Array(numBytes)))
    }
}

export interface HashFn {
    name: string
    Nh: number //  Nh: The output size of the Hash function in bytes.
    sum(msg: Uint8Array): Uint8Array
}

export class Hash implements HashFn {
    readonly Nh: number
    readonly nobleFn: CHash

    constructor(public readonly name: string) {
        switch (name) {
            case Hash.ID.SHA1:
                this.Nh = 20
                this.nobleFn = sha1
                break
            case Hash.ID.SHA256:
                this.Nh = 32
                this.nobleFn = sha256
                break
            case Hash.ID.SHA384:
                this.Nh = 48
                this.nobleFn = sha384
                break
            case Hash.ID.SHA512:
                this.Nh = 64
                this.nobleFn = sha512
                break
            default:
                throw new Error(`invalid hash name: ${name}`)
        }
    }

    sum(msg: Uint8Array): Uint8Array {
        return this.nobleFn(msg)
    }
}

/* eslint-disable-next-line @typescript-eslint/no-namespace */
export namespace Hash {
    export const ID = {
        SHA1: 'SHA-1',
        SHA256: 'SHA-256',
        SHA384: 'SHA-384',
        SHA512: 'SHA-512'
    } as const
    export type ID = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512'
}

export interface MACOps {
    sign(msg: Uint8Array): Uint8Array
    verify(msg: Uint8Array, output: Uint8Array): boolean
}

export interface MACFn {
    Nm: number // The output size of the MAC() function in bytes.
    with_key(key: Uint8Array): MACOps
}

export class Hmac implements MACFn {
    readonly Nm: number
    readonly hashFn: CHash

    constructor(public hash: string) {
        this.Nm = new Hash(hash).Nh
        this.hashFn = new Hash(hash).nobleFn
    }

    with_key(key: Uint8Array): MACOps {
        return new Hmac.Macops(key, this.hashFn)
    }

    private static Macops = class implements MACOps {
        constructor(
            private readonly key: Uint8Array,
            private readonly hash: CHash
        ) {}

        sign(msg: Uint8Array): Uint8Array {
            return hmac(this.hash, this.key, msg)
        }

        verify(msg: Uint8Array, output: Uint8Array): boolean {
            return ctEqual(output, this.sign(msg))
        }
    }
}

export interface KDFFn {
    Nx: number // The output size of the Extract() function in bytes.
    extract(salt: Uint8Array, ikm: Uint8Array): Uint8Array
    expand(prk: Uint8Array, info: Uint8Array, lenBytes: number): Uint8Array
}

export class Hkdf implements KDFFn {
    readonly Nx: number
    readonly hashFn: CHash

    constructor(public hash: string) {
        this.Nx = new Hash(hash).Nh
        this.hashFn = new Hash(hash).nobleFn
    }

    extract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
        return extract(this.hashFn, ikm, salt)
    }

    expand(prk: Uint8Array, info: Uint8Array, lenBytes: number): Uint8Array {
        return expand(this.hashFn, prk, info, lenBytes)
    }
}

export interface KSFFn {
    readonly name: string
    readonly harden: (input: Uint8Array) => Uint8Array
}

export const IdentityKSFFn: KSFFn = { name: 'Identity', harden: (x) => x } as const

export const ScryptKSFFn: KSFFn = {
    name: 'scrypt',
    harden: (msg: Uint8Array): Uint8Array => scrypt(msg, new Uint8Array(), { N: 32768, r: 8, p: 1 })
} as const

export interface AKEKeyPair {
    private_key: Uint8Array
    public_key: Uint8Array
}

export interface AKEExportKeyPair {
    private_key: number[]
    public_key: number[]
}

export interface AKEFn {
    readonly Nsk: number // Nsk: The size of AKE private keys.
    readonly Npk: number // Npk: The size of AKE public keys.
    deriveDHKeyPair(seed: Uint8Array): Promise<AKEKeyPair>
    generateDHKeyPair(): Promise<AKEKeyPair>
}

export interface OPRFFn {
    readonly Noe: number // Noe: The size of a serialized OPRF group element.
    readonly hash: string // hash: Name of the hash function used.
    readonly id: string // id: Identifier of the OPRF.
    readonly name: string // name: Name of the OPRF function.
    blind(input: Uint8Array): Promise<{ blind: Uint8Array; blindedElement: Uint8Array }>
    evaluate(key: Uint8Array, blinded: Uint8Array): Promise<Uint8Array>
    finalize(input: Uint8Array, blind: Uint8Array, evaluation: Uint8Array): Promise<Uint8Array>
    deriveOPRFKey(seed: Uint8Array): Promise<Uint8Array>
}
