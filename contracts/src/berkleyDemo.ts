import {
    Mina,
    isReady,
    PrivateKey,
    Field, UInt64,
    PublicKey,
    Proof,
    fetchLastBlock, fetchAccount,
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
const start = new Date().getTime()
console.log('compiling program and smart contract...');
await Token.compile();
await SSO.compile()
const finished = (new Date().getTime() - start) / 1000;
console.log("took: " + finished);
let zkapp = new SSO(PublicKey.fromBase58(zkAppAddress));
await fetchLastBlock();
await fetchAccount({publicKey: PublicKey.fromBase58(zkAppAddress)});

const getScopesByRole = (roleName: string): Scope[] => {
    return publicInfo.roles_by_name[roleName].scopes.map((value: Scope) => {
        return new Scope({name: value.name, value: Field(value.value)})
    });
}


const getAuthState = (roleName: string, networkTime: UInt64): AuthState => {
    const exp = networkTime.add(new UInt64(3599));
    const scopes = getScopesByRole(roleName);
    return AuthState.init(
        zkapp.userStoreCommitment.get().toConstant(),
        zkapp.roleStoreCommitment.get().toConstant(),
        networkTime,
        exp,
        scopes,
    );
}

const getWitness = (merklePath: string[]): SSOMerkleWitness => {
    return SSOMerkleWitness.fromFields(merklePath.map((s: string) => {
        return Field(s)
    }));
}

const login = async (priv: PrivateKey, role: string, userMerklePath: SSOMerkleWitness): Promise<Proof<AuthState>> => {
    const networkTime = await Mina.getNetworkState().timestamp;
    const scopes = getScopesByRole(role);
    const authState = getAuthState(role, networkTime);
    const privateArgs = PrivateAuthArgs.init(networkTime, priv, Role.init(role, scopes))
    const rolePath = getWitness(publicInfo.roles[publicInfo.roles_by_name[role].hash]);
    return await Token.init(authState, privateArgs, userMerklePath, rolePath)
}

const authorize = async (token: Proof<AuthState>, scope: Scope): Promise<boolean> => {
    const pub = PublicKey.fromBase58("B62qjrPCFTq4A4EJQLihvVVJSM3VMeVhTd9K8Vyxcn4TY3Yx845jV9p");
    await fetchAccount({publicKey: pub});
    let zkapp = new SSO(pub);
    try {
        zkapp.authorize(token, scope)
        const authorizerKey = PrivateKey.fromBase58("EKF6vSvUiZ8JXLhCNzVUMniqo9xisktsej94MbT8cBHyHMUfaPSm")
        const tx = await Mina.transaction(authorizerKey, () => {
            zkapp.authorize(token, scope)
        })
        const p = await tx.prove();
        console.log(p);
        return true
    } catch(e) {
        console.log("unauthorized! " + e)
        return false
    }
}

try {
    console.log("logging in with pet_manager.");
    let start = new Date().getTime()
    const userPath = getWitness(publicInfo.users[users[1].hash().toString()]);
    let token;
    try {
        token = await login(PrivateKey.fromBase58(userKeys[1]), "pet_manager", userPath);
        console.log("logged in...");
        const jsonToken = token.toJSON();
        fs.writeFileSync('token.json', JSON.stringify(jsonToken));
    } catch (e) {
        console.log("login failed: " + e)
    }
    const finished = (new Date().getTime() - start) / 1000;
    console.log("took " + finished + " seconds");


    if (!token) {
        process.exit(1)
    }
    console.log("** authorization **")
    let Berkley = Mina.BerkeleyQANet("https://proxy.berkeley.minaexplorer.com/graphql");
    Mina.setActiveInstance(Berkley);
    start = new Date().getTime()
    const authZ1 = await authorize(token, new Scope({name: "pet.write", value: Field(28689)}))
    const finished1 = (new Date().getTime() - start) / 1000;
    if (authZ1) {
        console.log('authorized for pet.write. finished in: ' + finished1 + " seconds");
    } else {
        console.log('unauthorized for pet.write. finished in: ' + finished1 + "seconds");
    }
    const authZ2 = await authorize(token, new Scope({name: "user.write", value: Field(28694)}))
    const finished2 = (new Date().getTime() - start) / 1000;
    if (authZ2) {
        console.log('authorized for user.write. finished in: ' + finished2 + " seconds");
    } else {
        console.log('unauthorized for user.write. finished in: ' + finished2 + "seconds");
    }
} catch (e) {
    console.error("AuthN failed: " + e);
    process.exit(1);
}

process.exit(0);
