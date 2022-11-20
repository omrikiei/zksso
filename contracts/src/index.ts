import { MerkleWitness } from 'snarkyjs';
export const tree_height = 5; // capped by 10 users
export class SSOMerkleWitness extends MerkleWitness(tree_height) {}
import { User, Role, Scope } from './sso-lib.js'
import { AuthState, PrivateAuthArgs, Token } from './token.js';
import { SSO } from './SSO.js'

export const token_lifetime_secs = 3600;
export {User, Role, Scope}
export { AuthState, PrivateAuthArgs, Token }
export { SSO }