import { MerkleWitness } from 'snarkyjs';

export const tree_height = 500; // capped by 1000 users
export const token_lifetime_secs = 3600;
export class SSOMerkleWitness extends MerkleWitness(tree_height) {}
