// @ts-ignore
import fs from 'fs';
import {
    Field,
    isReady,
    MerkleTree,
    MerkleWitness,
    Mina,
    PublicKey,
    UInt64,
    fetchAccount,
    PrivateKey,
} from "snarkyjs";

const updateChainState = true

await isReady;

import {Scope, User, Role} from '../sso-lib.js'
import {SSO} from "../SSO.js";
let rawData = fs.readFileSync('./src/db/db.json');
let keys = JSON.parse(fs.readFileSync('./keys/berkley.json').toString());
const db = JSON.parse(rawData.toString());
const scopes = new Map<number, Scope>;
const roles = new Array<Field>;
const users = new Array<Field>;
const undefinedScope = new Scope({name: "undefined", value: Field(0)})
const rolesByName = new Map<string, {hash: Field, scopes: Scope[]}>;
class TreeMerkleWitness extends MerkleWitness(5) {}

for (const id in db.scopes) {
    scopes.set(parseInt(id), new Scope({name: db.scopes[id], value: Field(id)}));
}

for (const role in db.roles) {
    const roleScopes = db.roles[role].map((id: number) => {
        return scopes.get(id)
    })
    while (roleScopes.length < 10) {
        roleScopes.push(undefinedScope)
    }
    const roleHash = Role.init(role, roleScopes).hash();
    roles.push(roleHash);
    rolesByName.set(role, {
        hash: roleHash,
        scopes: roleScopes,
    });
}

for (const pubKey in db.users) {
    const roleName = db.users[pubKey]
    const roleHash = rolesByName.get(roleName) || {hash: Field(0)};
    users.push(new User({publicKey: PublicKey.fromBase58(pubKey), role: roleHash.hash}).hash())
}

const userMerkleTree = new MerkleTree(5);
const roleMerkleTree = new MerkleTree(5);

users.forEach((user, i) => {
    userMerkleTree.setLeaf(BigInt(i), user);
})

roles.forEach((role, i) => {
    roleMerkleTree.setLeaf(BigInt(i), role);
})

const publicInfo = {
    users: new Map<string, string[]>(),
    roles: new Map<string, string[]>(),
};

users.forEach((userHash, i) => {
    const userWitness = new TreeMerkleWitness(userMerkleTree.getWitness(BigInt(i)));
    const hash = userMerkleTree.getNode(0, BigInt(i));
    publicInfo.users.set(hash.toString(), userWitness.toFields().map((f) => { return f.toString()}));
})

roles.forEach((roleHash, i) => {
    const roleWitness = new TreeMerkleWitness(roleMerkleTree.getWitness(BigInt(i)));
    const hash = roleMerkleTree.getNode(0, BigInt(i));
    publicInfo.roles.set(hash.toString(), roleWitness.toFields().map((f) => {return f.toString()}));
})

try {
    console.log("roleRoot: " + roleMerkleTree.getRoot().toString());
    console.log("userRoot: " + userMerkleTree.getRoot().toString());
    if (updateChainState) {
        let Berkley = Mina.BerkeleyQANet("https://proxy.berkeley.minaexplorer.com/graphql");
        Mina.setActiveInstance(Berkley);
        const priv = PrivateKey.fromBase58(keys.privateKey);
        const pub = PublicKey.fromBase58(keys.publicKey);
        await fetchAccount(keys.publicKey);
        let zkapp = new SSO(pub);
        let updateTx = await Mina.transaction({feePayerKey: priv, fee: 0.1 * 1e9, memo: "update SSO commitments"}, () => {
            console.log('update');
            zkapp.updateStateCommitments(
                userMerkleTree.getRoot(),
                roleMerkleTree.getRoot(),
                UInt64.from(3600)
            );
            console.log('updated');
            zkapp.requireSignature();
        });

        await updateTx.prove();
        updateTx.sign([priv]);
        await updateTx.sign().send();
    }

    console.log("state updated, writing public info...");
    fs.writeFileSync('public_info.json', JSON.stringify({
        users: Object.fromEntries(publicInfo.users),
        roles: Object.fromEntries(publicInfo.roles),
        roles_by_name: Object.fromEntries(rolesByName)
    }));
    console.log("done...")
} catch(e) {
    console.error("failed building DB trees: "+ e);
}
