import { Field, Poseidon, PrivateKey, PublicKey, Struct } from 'snarkyjs';

export { User, Role, Scope };

// A user represents a user in the system
class User extends Struct({
  publicKey: PublicKey,
  role: Field,
}) {
  static fromPrivateKey(privateKey: PrivateKey, roleHash: Field): User {
    return new User({
      publicKey: privateKey.toPublicKey(),
      role: roleHash,
    });
  }

  hash(): Field {
    return Poseidon.hash([...this.publicKey.toFields(), this.role]);
  }
}

class Scope extends Struct({
  name: String,
  value: Field,
}) {
  init(name: string, value: number) {
    this.name = name;
    this.value = Field(value);
  }
}

class Role extends Struct({
  name: String,
  scopes: [
    Scope,
    Scope,
    Scope,
    Scope,
    Scope,
    Scope,
    Scope,
    Scope,
    Scope,
    Scope,
  ],
}) {
  static init(name: string, grantedScopes: Scope[]) {
    let scopes = new Array(10);
    for (let i = 0; i < 10; i++) {
      if (grantedScopes.length <= i) {
        scopes[i] = new Scope({ name: 'undefined', value: Field(0) });
        continue;
      }
      scopes[i] = grantedScopes[i];
    }
    return new Role({
      name: name,
      scopes: scopes,
    });
  }

  hash(): Field {
    return Poseidon.hash([
      ...this.scopes.map((x) => {
        return x.value;
      }),
    ]);
  }
}
