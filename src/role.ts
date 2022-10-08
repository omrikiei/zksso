import {
    Field,
    CircuitValue,
    Poseidon,
    prop, arrayProp,
} from 'snarkyjs';

export { Role }

// A user represents a user in the system
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