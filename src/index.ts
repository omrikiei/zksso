import { SSO } from './SSO';
import {Field, Experimental} from "snarkyjs";

export default SSO;
export const tree_height = 500 // capped by 1000 users
export const MerkleWitness = Experimental.MerkleWitness(tree_height)
export interface TreeWitness {
    // eslint-disable-next-line no-unused-vars
    calculateRoot(leaf: Field): Field;
    calculateIndex(): Field;
}