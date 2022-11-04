import {
  arrayProp,
  CircuitString,
  CircuitValue,
  Field,
  Poseidon,
  PrivateKey,
  prop,
  PublicKey,
} from 'snarkyjs';

export { User, Role };

// A user represents a user in the system
class User extends CircuitValue {
  @prop publicKey: PublicKey;
  @prop roleName: Field;

  constructor(publicKey: PublicKey, roleName: Field) {
    super();
    this.publicKey = publicKey;
    this.roleName = roleName;
  }

  static fromPrivateKey(privateKey: PrivateKey, roleName: Field): User {
    return new User(privateKey.toPublicKey(), roleName);
  }

  hash(): Field {
    return Poseidon.hash(this.toFields());
  }
}

class Role extends CircuitValue {
  @prop name: CircuitString;
  @arrayProp(CircuitString, 10) scopes: CircuitString[];

  constructor(name: string, grantedScopes: string[]) {
    super();
    this.name = CircuitString.fromString(name);
    this.scopes = new Array(10);
    for (let i = 0; i < 10; i++) {
      this.scopes[i] = CircuitString.fromString('');
    }
    grantedScopes.map((v, i) => (this.scopes[i] = CircuitString.fromString(v)));
  }

  hash(): Field {
    return Poseidon.hash([
      this.name.hash(),
      ...this.scopes.map((v) => {
        return v.hash();
      }),
    ]);
  }
}
