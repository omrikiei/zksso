import {arrayProp, CircuitString, CircuitValue, Field, Poseidon, PrivateKey, prop, PublicKey} from "snarkyjs";

export { User, Role}

// A user represents a user in the system
class User extends CircuitValue {
    @prop publicKey: PublicKey;
    @prop roleName: Field;

    static fromPrivateKey(privateKey: PrivateKey, roleName: Field): User {
        return new User(privateKey.toPublicKey(), roleName);
    }

    hash(): Field {
        return Poseidon.hash(this.toFields());
    }
}

class Role extends CircuitValue {
    @prop name: CircuitString;
    @arrayProp(Field, 10) scopes: CircuitString[];

    constructor(name: string, grantedScopes: string[]) {
        super();
        this.name = CircuitString.fromString(name);
        this.scopes = grantedScopes.map((v) => CircuitString.fromString(v));
    }

    hash(): Field {
        return Poseidon.hash(this.toFields());
    }
}