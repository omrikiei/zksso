// A user represents a user in the system
import {arrayProp, CircuitValue, Field, Poseidon, PrivateKey, prop, PublicKey} from "snarkyjs";

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
    @prop name: Field;
    @arrayProp(Field, 10) scopes: Field[];

    constructor(name: Field, grantedScopes: string[]) {
        super();
        this.name = name;
        this.scopes = grantedScopes.map((v) => Field(v));
    }

    hash(): Field {
        return Poseidon.hash(this.toFields());
    }
}