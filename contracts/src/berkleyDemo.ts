import {
    Mina,
    isReady,
    PrivateKey,
    Field, UInt64,
    PublicKey,
    fetchLastBlock, fetchAccount
} from 'snarkyjs';
import {SSO} from './SSO.js';
import {AuthState, PrivateAuthArgs, Token} from './token.js';
import {User, Role, Scope} from './sso-lib.js';
import {SSOMerkleWitness} from './index.js';

await isReady;

let zkAppAddress = "B62qjrPCFTq4A4EJQLihvVVJSM3VMeVhTd9K8Vyxcn4TY3Yx845jV9p";
import fs from 'fs';

const userKeys = [
    "EKE3ykLNgXcjPTejnGMkZXiLqwdr7dwh19yEpC8pQyMYSWQyQTjo", // admin
    "EKEYLzo6gsAGx5R1jruttK5uvKYMqKxNERFYE3A8cQ6kPs6zVihv", // pet_manager
    "EKFQrk4o5bUKqEL1hsibmMhMd6WP1vLJ5auAstwGsnuxXacoeXAv", // sales_rep
    "EKER4JS1c689mhGiPG3C5kUxBgCo2GwqEfrgVmuirNN4Q1GNuA2e", // store_manager
]

const roleHashes = {
    "admin": "8939864419918693936425225251946324820862288742717869950247541739332425557503",
    "pet_manager": "13359176758427436387153874054273913605393276458521622582065421040715372293270",
    "sales_rep": "1675612965502786282597222473836848116640001808003589160700917624903874641356",
    "store_manager": "1367556466317787805632544481384783606751535878470802167784281726376388906113"
}

const publicInfo = JSON.parse(fs.readFileSync('./public_info.json').toString());

const users = new Array<User>();
users.push(User.fromPrivateKey(PrivateKey.fromBase58(userKeys[0]), Field(roleHashes.admin)))
users.push(User.fromPrivateKey(PrivateKey.fromBase58(userKeys[1]), Field(roleHashes.pet_manager)))
users.push(User.fromPrivateKey(PrivateKey.fromBase58(userKeys[2]), Field(roleHashes.sales_rep)))
users.push(User.fromPrivateKey(PrivateKey.fromBase58(userKeys[3]), Field(roleHashes.store_manager)))

let Berkley = Mina.BerkeleyQANet("https://proxy.berkeley.minaexplorer.com/graphql");
Mina.setActiveInstance(Berkley);
console.log('compiling token...');
await Token.compile();
let zkapp = new SSO(PublicKey.fromBase58(zkAppAddress));
await fetchLastBlock();
await fetchAccount({publicKey: PublicKey.fromBase58(zkAppAddress)});
const networkTime = await Mina.getNetworkState().timestamp;
const exp = networkTime.add(new UInt64(3599));

const adminScopes = publicInfo.roles_by_name.admin.scopes.map((value: Scope) => {
    return new Scope({name: value.name, value: Field(value.value)})
});


const adminAuthState = AuthState.init(
    zkapp.userStoreCommitment.get().toConstant(),
    zkapp.roleStoreCommitment.get().toConstant(),
    networkTime,
    exp,
    adminScopes,
);

const adminPrivateAuthArgs = PrivateAuthArgs.init(networkTime, PrivateKey.fromBase58(userKeys[0]), Role.init("admin", adminScopes));

const rolePath = SSOMerkleWitness.fromFields(publicInfo.roles[publicInfo.roles_by_name.admin.hash].map((s: string) => {
    return Field(s)
}));
const userPath = SSOMerkleWitness.fromFields(publicInfo.users[users[0].hash().toString()].map((s: string) => {
    return Field(s)
}));

try {
    console.log("logging in with admin.");
    let token = await Token.init(adminAuthState, adminPrivateAuthArgs, userPath, rolePath);
    console.log("logged in...");


    let Berkley = Mina.BerkeleyQANet("https://proxy.berkeley.minaexplorer.com/graphql");
    Mina.setActiveInstance(Berkley);
    const pub = PublicKey.fromBase58("B62qjrPCFTq4A4EJQLihvVVJSM3VMeVhTd9K8Vyxcn4TY3Yx845jV9p");
    await fetchAccount({publicKey: pub});
    let zkapp = new SSO(pub);
    let updateTx = await Mina.transaction( () => {
        console.log('checking user.read authorization');
        zkapp.authorize(
            token,
            new Scope({name: "user.read", value: Field(28694)})
        );
        zkapp.requireSignature();
    });

    await updateTx.send();
    console.log('authorized');

} catch(e) {
    console.error("AuthN failed: "+ e);
}
