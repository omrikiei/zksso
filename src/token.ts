import {
    Field,
    CircuitValue,
    prop,
    Experimental, UInt64, CircuitString, PrivateKey, SelfProof, Circuit, arrayProp, Poseidon
} from 'snarkyjs';
import ZkProgram = Experimental.ZkProgram;
import {Role, User} from "./sso-lib";
import {hashWithPrefix} from "snarkyjs/dist/web/lib/hash";
import {BaseMerkleWitness} from "snarkyjs/dist/web/lib/merkle_tree";

export {AuthState, PrivateAuthArgs, Token}

class AuthState extends CircuitValue {
    @prop userStoreCommitment: Field
    @prop roleStoreCommitment: Field
    @prop iat: UInt64
    @prop exp: UInt64
    @arrayProp(Field, 10) scopes: Field[]

    constructor(
        userStoreCommitment: Field,
        roleStoreCommitment: Field,
        iat: UInt64,
        exp: UInt64,
        scopes: Field[],
    ) {
        super();
        this.userStoreCommitment = userStoreCommitment;
        this.roleStoreCommitment = roleStoreCommitment;
        this.iat = iat;
        this.exp = exp;
        this.scopes = scopes.map((v, i) =>
            hashWithPrefix(exp.toString(), v.toFields())
        );
    }

    hash() {
        return Poseidon.hash(this.toFields())
    }
}

class PrivateAuthArgs extends CircuitValue {
    @prop privateKey: PrivateKey
    @prop role: Role
    @prop userProof: BaseMerkleWitness
    @prop roleProof: BaseMerkleWitness

    constructor(
        privateKey: PrivateKey,
        role: Role,
        userProof: BaseMerkleWitness,
        roleProof: BaseMerkleWitness,
    ) {
        super();
        this.privateKey = privateKey
        this.role = role
        this.userProof = userProof
        this.roleProof = roleProof
    }

    hash() {
        return Poseidon.hash(this.toFields())
    }
}

const Token = ZkProgram({
    publicInput: AuthState,
    methods: {
        authenticate: {
            privateInputs: [PrivateAuthArgs],
            method(
                publicInput: AuthState,
                privateAuthArgs: PrivateAuthArgs
            ) {
                const user = User.fromPrivateKey(privateAuthArgs.privateKey, privateAuthArgs.role.name)
                const now = UInt64.from(new Date().getTime());
                publicInput.exp.assertGt(now)
                publicInput.iat.assertLte(now)
                privateAuthArgs.roleProof.calculateRoot(privateAuthArgs.role.hash()).assertEquals(publicInput.roleStoreCommitment);
                privateAuthArgs.userProof.calculateRoot(user.hash()).assertEquals(publicInput.userStoreCommitment);
            },
        },
        authorize: {
            privateInputs: [SelfProof, CircuitString],
            method(
                publicInput: AuthState,
                authProof: SelfProof<AuthState>,
                scope: CircuitString
            ) {
                authProof.verify();
                let authorized = Field(0);
                const hashedScope = hashWithPrefix(publicInput.exp.toString(), scope.toFields())
                publicInput.scopes.forEach((v) => {authorized = Circuit.if(v.equals(hashedScope), authorized.add(0), authorized)})
                authorized.assertGt(0);
            },
        },
    },
})