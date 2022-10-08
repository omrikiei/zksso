import {
    Field,
    CircuitValue,
    Poseidon,
    prop, PrivateKey, PublicKey,
} from 'snarkyjs';

// A user represents a user in the system
export default class User extends CircuitValue {
    @prop publicKey: PublicKey;
    @prop roleName: Field;
  
    static fromPrivateKey(privateKey: PrivateKey, roleName: Field): User {
      return new User(privateKey.toPublicKey(), roleName);
    }
  
    hash(): Field {
      return Poseidon.hash(this.toFields());
    }
}