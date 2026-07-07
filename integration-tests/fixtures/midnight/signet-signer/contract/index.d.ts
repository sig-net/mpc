import type * as __compactRuntime from '@midnight-ntwrk/compact-runtime';

export type Witnesses<PS> = {
  callerSecretKey(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, Uint8Array];
}

export type ImpureCircuits<PS> = {
  sign(context: __compactRuntime.CircuitContext<PS>,
       payload_0: Uint8Array,
       keyVersion_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  sign_bidirectional(context: __compactRuntime.CircuitContext<PS>,
                     evmTo_0: Uint8Array,
                     evmChainId_0: bigint,
                     evmNonce_0: bigint,
                     evmGasLimit_0: bigint,
                     evmMaxFee_0: bigint,
                     evmPriorityFee_0: bigint,
                     evmValue_0: bigint,
                     funcSig_0: Uint8Array,
                     args_0: Uint8Array[],
                     argCount_0: bigint,
                     caip2Id_0: Uint8Array,
                     keyVersion_0: bigint,
                     dest_0: Uint8Array,
                     params_0: Uint8Array,
                     outputSchema_0: Uint8Array,
                     respondSchema_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  respond(context: __compactRuntime.CircuitContext<PS>,
          requestId_0: Uint8Array,
          bigRx_0: Uint8Array,
          bigRy_0: Uint8Array,
          s_0: Uint8Array,
          recoveryId_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  respond_bidirectional(context: __compactRuntime.CircuitContext<PS>,
                        requestId_0: Uint8Array,
                        serializedOutput_0: Uint8Array,
                        outputLen_0: bigint,
                        bigRx_0: Uint8Array,
                        bigRy_0: Uint8Array,
                        s_0: Uint8Array,
                        recoveryId_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
}

export type ProvableCircuits<PS> = {
  sign(context: __compactRuntime.CircuitContext<PS>,
       payload_0: Uint8Array,
       keyVersion_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  sign_bidirectional(context: __compactRuntime.CircuitContext<PS>,
                     evmTo_0: Uint8Array,
                     evmChainId_0: bigint,
                     evmNonce_0: bigint,
                     evmGasLimit_0: bigint,
                     evmMaxFee_0: bigint,
                     evmPriorityFee_0: bigint,
                     evmValue_0: bigint,
                     funcSig_0: Uint8Array,
                     args_0: Uint8Array[],
                     argCount_0: bigint,
                     caip2Id_0: Uint8Array,
                     keyVersion_0: bigint,
                     dest_0: Uint8Array,
                     params_0: Uint8Array,
                     outputSchema_0: Uint8Array,
                     respondSchema_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  respond(context: __compactRuntime.CircuitContext<PS>,
          requestId_0: Uint8Array,
          bigRx_0: Uint8Array,
          bigRy_0: Uint8Array,
          s_0: Uint8Array,
          recoveryId_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  respond_bidirectional(context: __compactRuntime.CircuitContext<PS>,
                        requestId_0: Uint8Array,
                        serializedOutput_0: Uint8Array,
                        outputLen_0: bigint,
                        bigRx_0: Uint8Array,
                        bigRy_0: Uint8Array,
                        s_0: Uint8Array,
                        recoveryId_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
}

export type PureCircuits = {
}

export type Circuits<PS> = {
  sign(context: __compactRuntime.CircuitContext<PS>,
       payload_0: Uint8Array,
       keyVersion_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  sign_bidirectional(context: __compactRuntime.CircuitContext<PS>,
                     evmTo_0: Uint8Array,
                     evmChainId_0: bigint,
                     evmNonce_0: bigint,
                     evmGasLimit_0: bigint,
                     evmMaxFee_0: bigint,
                     evmPriorityFee_0: bigint,
                     evmValue_0: bigint,
                     funcSig_0: Uint8Array,
                     args_0: Uint8Array[],
                     argCount_0: bigint,
                     caip2Id_0: Uint8Array,
                     keyVersion_0: bigint,
                     dest_0: Uint8Array,
                     params_0: Uint8Array,
                     outputSchema_0: Uint8Array,
                     respondSchema_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  respond(context: __compactRuntime.CircuitContext<PS>,
          requestId_0: Uint8Array,
          bigRx_0: Uint8Array,
          bigRy_0: Uint8Array,
          s_0: Uint8Array,
          recoveryId_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  respond_bidirectional(context: __compactRuntime.CircuitContext<PS>,
                        requestId_0: Uint8Array,
                        serializedOutput_0: Uint8Array,
                        outputLen_0: bigint,
                        bigRx_0: Uint8Array,
                        bigRy_0: Uint8Array,
                        s_0: Uint8Array,
                        recoveryId_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
}

export type Ledger = {
  readonly signetNonce: bigint;
}

export type ContractReferenceLocations = any;

export declare const contractReferenceLocations : ContractReferenceLocations;

export declare class Contract<PS = any, W extends Witnesses<PS> = Witnesses<PS>> {
  witnesses: W;
  circuits: Circuits<PS>;
  impureCircuits: ImpureCircuits<PS>;
  provableCircuits: ProvableCircuits<PS>;
  constructor(witnesses: W);
  initialState(context: __compactRuntime.ConstructorContext<PS>): Promise<__compactRuntime.ConstructorResult<PS>>;
}

export declare function ledger(state: __compactRuntime.StateValue | __compactRuntime.ChargedState): Ledger;
export declare const pureCircuits: PureCircuits;
export declare const expectedVk: Record<string, string>;
