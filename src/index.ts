import { Experimental } from 'snarkyjs';

export const tree_height = 500; // capped by 1000 users
export class MerkleWitness extends Experimental.MerkleWitness(tree_height) {}
/*export interface TreeWitness extends CircuitValue {
  // eslint-disable-next-line no-unused-vars
  calculateRoot(leaf: Field): Field;
  calculateIndex(): Field;
}*/
