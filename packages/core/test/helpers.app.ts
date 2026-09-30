import algosdk from 'algosdk';
import type { FalconerClients } from '../src/networks.js';
import type { LocalAccount } from './helpers.js';

/**
 * Deploy an application that stores one address in global state.
 *
 * This is the shape Falconer cares about: an app that keeps an admin or
 * treasury address in state, where the named account is not the creator.
 */
export async function createAppNaming(
  clients: FalconerClients,
  deployer: LocalAccount,
  named: string,
  stateKey = 'admin',
  approvalSource?: string,
): Promise<bigint> {
  const approval =
    approvalSource ??
    `#pragma version 8
txn ApplicationID
bz handle_create
int 1
return
handle_create:
byte "${stateKey}"
txna ApplicationArgs 0
app_global_put
int 1
return
`;
  const clear = `#pragma version 8
int 1
return
`;
  const ap = await clients.algod.compile(approval).do();
  const cp = await clients.algod.compile(clear).do();
  const b64 = (s: string) =>
    Uint8Array.from((globalThis as any).Buffer.from(s, 'base64'));

  const sp = await clients.algod.getTransactionParams().do();
  const txn = algosdk.makeApplicationCreateTxnFromObject({
    sender: deployer.address,
    suggestedParams: sp,
    onComplete: algosdk.OnApplicationComplete.NoOpOC,
    approvalProgram: b64(ap.result),
    clearProgram: b64(cp.result),
    numGlobalByteSlices: 1,
    numGlobalInts: 0,
    numLocalByteSlices: 0,
    numLocalInts: 0,
    appArgs: [algosdk.decodeAddress(named).publicKey],
  });
  const { txid } = await clients.algod
    .sendRawTransaction(txn.signTxn(deployer.sk))
    .do();
  const res = await algosdk.waitForConfirmation(clients.algod, txid, 10);
  return BigInt(res.applicationIndex ?? 0);
}

/**
 * An approval program that grants its creator nothing: it stores the named
 * address on creation, then refuses every update and deletion outright,
 * whoever asks. Creating it confers no power over it at all.
 */
export const IMMUTABLE_APPROVAL = `#pragma version 8
txn ApplicationID
bz handle_create
txn OnCompletion
int UpdateApplication
==
bnz refuse
txn OnCompletion
int DeleteApplication
==
bnz refuse
int 1
return
refuse:
int 0
return
handle_create:
byte "admin"
txna ApplicationArgs 0
app_global_put
int 1
return
`;
