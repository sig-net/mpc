import * as __compactRuntime from '@midnight-ntwrk/compact-runtime';
__compactRuntime.checkRuntimeVersion('0.18.0-rc.0');

const _descriptor_0 = new __compactRuntime.CompactTypeBytes(32);

const _descriptor_1 = new __compactRuntime.CompactTypeBytes(128);

const _descriptor_2 = new __compactRuntime.CompactTypeUnsignedInteger(255n, 1);

const _descriptor_3 = new __compactRuntime.CompactTypeUnsignedInteger(65535n, 2);

const _descriptor_4 = new __compactRuntime.CompactTypeUnsignedInteger(18446744073709551615n, 8);

const _descriptor_5 = new __compactRuntime.CompactTypeBytes(20);

const _descriptor_6 = new __compactRuntime.CompactTypeUnsignedInteger(340282366920938463463374607431768211455n, 16);

const _descriptor_7 = new __compactRuntime.CompactTypeBytes(64);

const _descriptor_8 = new __compactRuntime.CompactTypeVector(4, _descriptor_0);

const _descriptor_9 = new __compactRuntime.CompactTypeUnsignedInteger(4294967295n, 4);

const _descriptor_10 = new __compactRuntime.CompactTypeBytes(288);

const _descriptor_11 = new __compactRuntime.CompactTypeBytes(224);

class _RespondSig_0 {
  alignment() {
    return _descriptor_0.alignment().concat(_descriptor_0.alignment().concat(_descriptor_0.alignment().concat(_descriptor_2.alignment())));
  }
  fromValue(value_0) {
    return {
      bigRx: _descriptor_0.fromValue(value_0),
      bigRy: _descriptor_0.fromValue(value_0),
      s: _descriptor_0.fromValue(value_0),
      recoveryId: _descriptor_2.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_0.toValue(value_0.bigRx).concat(_descriptor_0.toValue(value_0.bigRy).concat(_descriptor_0.toValue(value_0.s).concat(_descriptor_2.toValue(value_0.recoveryId))));
  }
}

const _descriptor_12 = new _RespondSig_0();

class _EventPart_0 {
  alignment() {
    return _descriptor_0.alignment().concat(_descriptor_11.alignment());
  }
  fromValue(value_0) {
    return {
      requestId: _descriptor_0.fromValue(value_0),
      tail: _descriptor_11.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_0.toValue(value_0.requestId).concat(_descriptor_11.toValue(value_0.tail));
  }
}

const _descriptor_13 = new _EventPart_0();

const _descriptor_14 = new __compactRuntime.CompactTypeBytes(256);

class _SignBiRespondSchema_0 {
  alignment() {
    return _descriptor_1.alignment();
  }
  fromValue(value_0) {
    return {
      respondSchema: _descriptor_1.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_1.toValue(value_0.respondSchema);
  }
}

const _descriptor_15 = new _SignBiRespondSchema_0();

class _RespondBiOutput_0 {
  alignment() {
    return _descriptor_1.alignment().concat(_descriptor_2.alignment());
  }
  fromValue(value_0) {
    return {
      serializedOutput: _descriptor_1.fromValue(value_0),
      outputLen: _descriptor_2.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_1.toValue(value_0.serializedOutput).concat(_descriptor_2.toValue(value_0.outputLen));
  }
}

const _descriptor_16 = new _RespondBiOutput_0();

class _SignBiArgs_0 {
  alignment() {
    return _descriptor_8.alignment();
  }
  fromValue(value_0) {
    return {
      args: _descriptor_8.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_8.toValue(value_0.args);
  }
}

const _descriptor_17 = new _SignBiArgs_0();

class _SignBiOutputSchema_0 {
  alignment() {
    return _descriptor_1.alignment();
  }
  fromValue(value_0) {
    return {
      outputSchema: _descriptor_1.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_1.toValue(value_0.outputSchema);
  }
}

const _descriptor_18 = new _SignBiOutputSchema_0();

class _SignBiCore_0 {
  alignment() {
    return _descriptor_4.alignment().concat(_descriptor_0.alignment().concat(_descriptor_9.alignment().concat(_descriptor_0.alignment().concat(_descriptor_0.alignment().concat(_descriptor_7.alignment())))));
  }
  fromValue(value_0) {
    return {
      nonce: _descriptor_4.fromValue(value_0),
      commitment: _descriptor_0.fromValue(value_0),
      keyVersion: _descriptor_9.fromValue(value_0),
      caip2Id: _descriptor_0.fromValue(value_0),
      dest: _descriptor_0.fromValue(value_0),
      params: _descriptor_7.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_4.toValue(value_0.nonce).concat(_descriptor_0.toValue(value_0.commitment).concat(_descriptor_9.toValue(value_0.keyVersion).concat(_descriptor_0.toValue(value_0.caip2Id).concat(_descriptor_0.toValue(value_0.dest).concat(_descriptor_7.toValue(value_0.params))))));
  }
}

const _descriptor_19 = new _SignBiCore_0();

class _SignBiEvm_0 {
  alignment() {
    return _descriptor_5.alignment().concat(_descriptor_4.alignment().concat(_descriptor_4.alignment().concat(_descriptor_4.alignment().concat(_descriptor_6.alignment().concat(_descriptor_6.alignment().concat(_descriptor_6.alignment().concat(_descriptor_2.alignment().concat(_descriptor_7.alignment()))))))));
  }
  fromValue(value_0) {
    return {
      evmTo: _descriptor_5.fromValue(value_0),
      evmChainId: _descriptor_4.fromValue(value_0),
      evmNonce: _descriptor_4.fromValue(value_0),
      evmGasLimit: _descriptor_4.fromValue(value_0),
      evmMaxFee: _descriptor_6.fromValue(value_0),
      evmPriorityFee: _descriptor_6.fromValue(value_0),
      evmValue: _descriptor_6.fromValue(value_0),
      argCount: _descriptor_2.fromValue(value_0),
      funcSig: _descriptor_7.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_5.toValue(value_0.evmTo).concat(_descriptor_4.toValue(value_0.evmChainId).concat(_descriptor_4.toValue(value_0.evmNonce).concat(_descriptor_4.toValue(value_0.evmGasLimit).concat(_descriptor_6.toValue(value_0.evmMaxFee).concat(_descriptor_6.toValue(value_0.evmPriorityFee).concat(_descriptor_6.toValue(value_0.evmValue).concat(_descriptor_2.toValue(value_0.argCount).concat(_descriptor_7.toValue(value_0.funcSig)))))))));
  }
}

const _descriptor_20 = new _SignBiEvm_0();

const _descriptor_21 = new __compactRuntime.CompactTypeVector(5, _descriptor_11);

class _SignBody_0 {
  alignment() {
    return _descriptor_4.alignment().concat(_descriptor_0.alignment().concat(_descriptor_0.alignment().concat(_descriptor_9.alignment().concat(_descriptor_0.alignment().concat(_descriptor_0.alignment().concat(_descriptor_7.alignment()))))));
  }
  fromValue(value_0) {
    return {
      nonce: _descriptor_4.fromValue(value_0),
      commitment: _descriptor_0.fromValue(value_0),
      payload: _descriptor_0.fromValue(value_0),
      keyVersion: _descriptor_9.fromValue(value_0),
      algo: _descriptor_0.fromValue(value_0),
      dest: _descriptor_0.fromValue(value_0),
      params: _descriptor_7.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_4.toValue(value_0.nonce).concat(_descriptor_0.toValue(value_0.commitment).concat(_descriptor_0.toValue(value_0.payload).concat(_descriptor_9.toValue(value_0.keyVersion).concat(_descriptor_0.toValue(value_0.algo).concat(_descriptor_0.toValue(value_0.dest).concat(_descriptor_7.toValue(value_0.params)))))));
  }
}

const _descriptor_22 = new _SignBody_0();

const _descriptor_23 = new __compactRuntime.CompactTypeVector(2, _descriptor_0);

const _descriptor_24 = __compactRuntime.CompactTypeBoolean;

class _Either_0 {
  alignment() {
    return _descriptor_24.alignment().concat(_descriptor_0.alignment().concat(_descriptor_0.alignment()));
  }
  fromValue(value_0) {
    return {
      is_left: _descriptor_24.fromValue(value_0),
      left: _descriptor_0.fromValue(value_0),
      right: _descriptor_0.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_24.toValue(value_0.is_left).concat(_descriptor_0.toValue(value_0.left).concat(_descriptor_0.toValue(value_0.right)));
  }
}

const _descriptor_25 = new _Either_0();

class _ContractAddress_0 {
  alignment() {
    return _descriptor_0.alignment();
  }
  fromValue(value_0) {
    return {
      bytes: _descriptor_0.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_0.toValue(value_0.bytes);
  }
}

const _descriptor_26 = new _ContractAddress_0();

export class Contract {
  witnesses;
  constructor(...args_0) {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`Contract constructor: expected 1 argument, received ${args_0.length}`);
    }
    const witnesses_0 = args_0[0];
    if (typeof(witnesses_0) !== 'object') {
      throw new __compactRuntime.CompactError('first (witnesses) argument to Contract constructor is not an object');
    }
    if (typeof(witnesses_0.callerSecretKey) !== 'function') {
      throw new __compactRuntime.CompactError('first (witnesses) argument to Contract constructor does not contain a function-valued field named callerSecretKey');
    }
    this.witnesses = witnesses_0;
    this.circuits = {
      sign: async (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`sign: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const payload_0 = args_1[1];
        const keyVersion_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('sign',
                                     'argument 1 (as invoked from Typescript)',
                                     'signet-signer.compact line 127 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(payload_0.buffer instanceof ArrayBuffer && payload_0.BYTES_PER_ELEMENT === 1 && payload_0.length === 32)) {
          __compactRuntime.typeError('sign',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'signet-signer.compact line 127 char 1',
                                     'Bytes<32>',
                                     payload_0)
        }
        if (!(typeof(keyVersion_0) === 'bigint' && keyVersion_0 >= 0n && keyVersion_0 <= 4294967295n)) {
          __compactRuntime.typeError('sign',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'signet-signer.compact line 127 char 1',
                                     'Uint<0..4294967296>',
                                     keyVersion_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(payload_0).concat(_descriptor_9.toValue(keyVersion_0)),
            alignment: _descriptor_0.alignment().concat(_descriptor_9.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._sign_0(context,
                                            partialProofData,
                                            payload_0,
                                            keyVersion_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      sign_bidirectional: async (...args_1) => {
        if (args_1.length !== 17) {
          throw new __compactRuntime.CompactError(`sign_bidirectional: expected 17 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const evmTo_0 = args_1[1];
        const evmChainId_0 = args_1[2];
        const evmNonce_0 = args_1[3];
        const evmGasLimit_0 = args_1[4];
        const evmMaxFee_0 = args_1[5];
        const evmPriorityFee_0 = args_1[6];
        const evmValue_0 = args_1[7];
        const funcSig_0 = args_1[8];
        const args_2 = args_1[9];
        const argCount_0 = args_1[10];
        const caip2Id_0 = args_1[11];
        const keyVersion_0 = args_1[12];
        const dest_0 = args_1[13];
        const params_0 = args_1[14];
        const outputSchema_0 = args_1[15];
        const respondSchema_0 = args_1[16];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('sign_bidirectional',
                                     'argument 1 (as invoked from Typescript)',
                                     'signet-signer.compact line 152 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(evmTo_0.buffer instanceof ArrayBuffer && evmTo_0.BYTES_PER_ELEMENT === 1 && evmTo_0.length === 20)) {
          __compactRuntime.typeError('sign_bidirectional',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'signet-signer.compact line 152 char 1',
                                     'Bytes<20>',
                                     evmTo_0)
        }
        if (!(typeof(evmChainId_0) === 'bigint' && evmChainId_0 >= 0n && evmChainId_0 <= 18446744073709551615n)) {
          __compactRuntime.typeError('sign_bidirectional',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'signet-signer.compact line 152 char 1',
                                     'Uint<0..18446744073709551616>',
                                     evmChainId_0)
        }
        if (!(typeof(evmNonce_0) === 'bigint' && evmNonce_0 >= 0n && evmNonce_0 <= 18446744073709551615n)) {
          __compactRuntime.typeError('sign_bidirectional',
                                     'argument 3 (argument 4 as invoked from Typescript)',
                                     'signet-signer.compact line 152 char 1',
                                     'Uint<0..18446744073709551616>',
                                     evmNonce_0)
        }
        if (!(typeof(evmGasLimit_0) === 'bigint' && evmGasLimit_0 >= 0n && evmGasLimit_0 <= 18446744073709551615n)) {
          __compactRuntime.typeError('sign_bidirectional',
                                     'argument 4 (argument 5 as invoked from Typescript)',
                                     'signet-signer.compact line 152 char 1',
                                     'Uint<0..18446744073709551616>',
                                     evmGasLimit_0)
        }
        if (!(typeof(evmMaxFee_0) === 'bigint' && evmMaxFee_0 >= 0n && evmMaxFee_0 <= 340282366920938463463374607431768211455n)) {
          __compactRuntime.typeError('sign_bidirectional',
                                     'argument 5 (argument 6 as invoked from Typescript)',
                                     'signet-signer.compact line 152 char 1',
                                     'Uint<0..340282366920938463463374607431768211456>',
                                     evmMaxFee_0)
        }
        if (!(typeof(evmPriorityFee_0) === 'bigint' && evmPriorityFee_0 >= 0n && evmPriorityFee_0 <= 340282366920938463463374607431768211455n)) {
          __compactRuntime.typeError('sign_bidirectional',
                                     'argument 6 (argument 7 as invoked from Typescript)',
                                     'signet-signer.compact line 152 char 1',
                                     'Uint<0..340282366920938463463374607431768211456>',
                                     evmPriorityFee_0)
        }
        if (!(typeof(evmValue_0) === 'bigint' && evmValue_0 >= 0n && evmValue_0 <= 340282366920938463463374607431768211455n)) {
          __compactRuntime.typeError('sign_bidirectional',
                                     'argument 7 (argument 8 as invoked from Typescript)',
                                     'signet-signer.compact line 152 char 1',
                                     'Uint<0..340282366920938463463374607431768211456>',
                                     evmValue_0)
        }
        if (!(funcSig_0.buffer instanceof ArrayBuffer && funcSig_0.BYTES_PER_ELEMENT === 1 && funcSig_0.length === 64)) {
          __compactRuntime.typeError('sign_bidirectional',
                                     'argument 8 (argument 9 as invoked from Typescript)',
                                     'signet-signer.compact line 152 char 1',
                                     'Bytes<64>',
                                     funcSig_0)
        }
        if (!(Array.isArray(args_2) && args_2.length === 4 && args_2.every((t) => t.buffer instanceof ArrayBuffer && t.BYTES_PER_ELEMENT === 1 && t.length === 32))) {
          __compactRuntime.typeError('sign_bidirectional',
                                     'argument 9 (argument 10 as invoked from Typescript)',
                                     'signet-signer.compact line 152 char 1',
                                     'Vector<4, Bytes<32>>',
                                     args_2)
        }
        if (!(typeof(argCount_0) === 'bigint' && argCount_0 >= 0n && argCount_0 <= 255n)) {
          __compactRuntime.typeError('sign_bidirectional',
                                     'argument 10 (argument 11 as invoked from Typescript)',
                                     'signet-signer.compact line 152 char 1',
                                     'Uint<0..256>',
                                     argCount_0)
        }
        if (!(caip2Id_0.buffer instanceof ArrayBuffer && caip2Id_0.BYTES_PER_ELEMENT === 1 && caip2Id_0.length === 32)) {
          __compactRuntime.typeError('sign_bidirectional',
                                     'argument 11 (argument 12 as invoked from Typescript)',
                                     'signet-signer.compact line 152 char 1',
                                     'Bytes<32>',
                                     caip2Id_0)
        }
        if (!(typeof(keyVersion_0) === 'bigint' && keyVersion_0 >= 0n && keyVersion_0 <= 4294967295n)) {
          __compactRuntime.typeError('sign_bidirectional',
                                     'argument 12 (argument 13 as invoked from Typescript)',
                                     'signet-signer.compact line 152 char 1',
                                     'Uint<0..4294967296>',
                                     keyVersion_0)
        }
        if (!(dest_0.buffer instanceof ArrayBuffer && dest_0.BYTES_PER_ELEMENT === 1 && dest_0.length === 32)) {
          __compactRuntime.typeError('sign_bidirectional',
                                     'argument 13 (argument 14 as invoked from Typescript)',
                                     'signet-signer.compact line 152 char 1',
                                     'Bytes<32>',
                                     dest_0)
        }
        if (!(params_0.buffer instanceof ArrayBuffer && params_0.BYTES_PER_ELEMENT === 1 && params_0.length === 64)) {
          __compactRuntime.typeError('sign_bidirectional',
                                     'argument 14 (argument 15 as invoked from Typescript)',
                                     'signet-signer.compact line 152 char 1',
                                     'Bytes<64>',
                                     params_0)
        }
        if (!(outputSchema_0.buffer instanceof ArrayBuffer && outputSchema_0.BYTES_PER_ELEMENT === 1 && outputSchema_0.length === 128)) {
          __compactRuntime.typeError('sign_bidirectional',
                                     'argument 15 (argument 16 as invoked from Typescript)',
                                     'signet-signer.compact line 152 char 1',
                                     'Bytes<128>',
                                     outputSchema_0)
        }
        if (!(respondSchema_0.buffer instanceof ArrayBuffer && respondSchema_0.BYTES_PER_ELEMENT === 1 && respondSchema_0.length === 128)) {
          __compactRuntime.typeError('sign_bidirectional',
                                     'argument 16 (argument 17 as invoked from Typescript)',
                                     'signet-signer.compact line 152 char 1',
                                     'Bytes<128>',
                                     respondSchema_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_5.toValue(evmTo_0).concat(_descriptor_4.toValue(evmChainId_0).concat(_descriptor_4.toValue(evmNonce_0).concat(_descriptor_4.toValue(evmGasLimit_0).concat(_descriptor_6.toValue(evmMaxFee_0).concat(_descriptor_6.toValue(evmPriorityFee_0).concat(_descriptor_6.toValue(evmValue_0).concat(_descriptor_7.toValue(funcSig_0).concat(_descriptor_8.toValue(args_2).concat(_descriptor_2.toValue(argCount_0).concat(_descriptor_0.toValue(caip2Id_0).concat(_descriptor_9.toValue(keyVersion_0).concat(_descriptor_0.toValue(dest_0).concat(_descriptor_7.toValue(params_0).concat(_descriptor_1.toValue(outputSchema_0).concat(_descriptor_1.toValue(respondSchema_0)))))))))))))))),
            alignment: _descriptor_5.alignment().concat(_descriptor_4.alignment().concat(_descriptor_4.alignment().concat(_descriptor_4.alignment().concat(_descriptor_6.alignment().concat(_descriptor_6.alignment().concat(_descriptor_6.alignment().concat(_descriptor_7.alignment().concat(_descriptor_8.alignment().concat(_descriptor_2.alignment().concat(_descriptor_0.alignment().concat(_descriptor_9.alignment().concat(_descriptor_0.alignment().concat(_descriptor_7.alignment().concat(_descriptor_1.alignment().concat(_descriptor_1.alignment())))))))))))))))
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._sign_bidirectional_0(context,
                                                          partialProofData,
                                                          evmTo_0,
                                                          evmChainId_0,
                                                          evmNonce_0,
                                                          evmGasLimit_0,
                                                          evmMaxFee_0,
                                                          evmPriorityFee_0,
                                                          evmValue_0,
                                                          funcSig_0,
                                                          args_2,
                                                          argCount_0,
                                                          caip2Id_0,
                                                          keyVersion_0,
                                                          dest_0,
                                                          params_0,
                                                          outputSchema_0,
                                                          respondSchema_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      respond: async (...args_1) => {
        if (args_1.length !== 6) {
          throw new __compactRuntime.CompactError(`respond: expected 6 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const requestId_0 = args_1[1];
        const bigRx_0 = args_1[2];
        const bigRy_0 = args_1[3];
        const s_0 = args_1[4];
        const recoveryId_0 = args_1[5];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('respond',
                                     'argument 1 (as invoked from Typescript)',
                                     'signet-signer.compact line 206 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(requestId_0.buffer instanceof ArrayBuffer && requestId_0.BYTES_PER_ELEMENT === 1 && requestId_0.length === 32)) {
          __compactRuntime.typeError('respond',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'signet-signer.compact line 206 char 1',
                                     'Bytes<32>',
                                     requestId_0)
        }
        if (!(bigRx_0.buffer instanceof ArrayBuffer && bigRx_0.BYTES_PER_ELEMENT === 1 && bigRx_0.length === 32)) {
          __compactRuntime.typeError('respond',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'signet-signer.compact line 206 char 1',
                                     'Bytes<32>',
                                     bigRx_0)
        }
        if (!(bigRy_0.buffer instanceof ArrayBuffer && bigRy_0.BYTES_PER_ELEMENT === 1 && bigRy_0.length === 32)) {
          __compactRuntime.typeError('respond',
                                     'argument 3 (argument 4 as invoked from Typescript)',
                                     'signet-signer.compact line 206 char 1',
                                     'Bytes<32>',
                                     bigRy_0)
        }
        if (!(s_0.buffer instanceof ArrayBuffer && s_0.BYTES_PER_ELEMENT === 1 && s_0.length === 32)) {
          __compactRuntime.typeError('respond',
                                     'argument 4 (argument 5 as invoked from Typescript)',
                                     'signet-signer.compact line 206 char 1',
                                     'Bytes<32>',
                                     s_0)
        }
        if (!(typeof(recoveryId_0) === 'bigint' && recoveryId_0 >= 0n && recoveryId_0 <= 255n)) {
          __compactRuntime.typeError('respond',
                                     'argument 5 (argument 6 as invoked from Typescript)',
                                     'signet-signer.compact line 206 char 1',
                                     'Uint<0..256>',
                                     recoveryId_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(requestId_0).concat(_descriptor_0.toValue(bigRx_0).concat(_descriptor_0.toValue(bigRy_0).concat(_descriptor_0.toValue(s_0).concat(_descriptor_2.toValue(recoveryId_0))))),
            alignment: _descriptor_0.alignment().concat(_descriptor_0.alignment().concat(_descriptor_0.alignment().concat(_descriptor_0.alignment().concat(_descriptor_2.alignment()))))
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._respond_0(context,
                                               partialProofData,
                                               requestId_0,
                                               bigRx_0,
                                               bigRy_0,
                                               s_0,
                                               recoveryId_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      respond_bidirectional: async (...args_1) => {
        if (args_1.length !== 8) {
          throw new __compactRuntime.CompactError(`respond_bidirectional: expected 8 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const requestId_0 = args_1[1];
        const serializedOutput_0 = args_1[2];
        const outputLen_0 = args_1[3];
        const bigRx_0 = args_1[4];
        const bigRy_0 = args_1[5];
        const s_0 = args_1[6];
        const recoveryId_0 = args_1[7];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('respond_bidirectional',
                                     'argument 1 (as invoked from Typescript)',
                                     'signet-signer.compact line 226 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(requestId_0.buffer instanceof ArrayBuffer && requestId_0.BYTES_PER_ELEMENT === 1 && requestId_0.length === 32)) {
          __compactRuntime.typeError('respond_bidirectional',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'signet-signer.compact line 226 char 1',
                                     'Bytes<32>',
                                     requestId_0)
        }
        if (!(serializedOutput_0.buffer instanceof ArrayBuffer && serializedOutput_0.BYTES_PER_ELEMENT === 1 && serializedOutput_0.length === 128)) {
          __compactRuntime.typeError('respond_bidirectional',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'signet-signer.compact line 226 char 1',
                                     'Bytes<128>',
                                     serializedOutput_0)
        }
        if (!(typeof(outputLen_0) === 'bigint' && outputLen_0 >= 0n && outputLen_0 <= 255n)) {
          __compactRuntime.typeError('respond_bidirectional',
                                     'argument 3 (argument 4 as invoked from Typescript)',
                                     'signet-signer.compact line 226 char 1',
                                     'Uint<0..256>',
                                     outputLen_0)
        }
        if (!(bigRx_0.buffer instanceof ArrayBuffer && bigRx_0.BYTES_PER_ELEMENT === 1 && bigRx_0.length === 32)) {
          __compactRuntime.typeError('respond_bidirectional',
                                     'argument 4 (argument 5 as invoked from Typescript)',
                                     'signet-signer.compact line 226 char 1',
                                     'Bytes<32>',
                                     bigRx_0)
        }
        if (!(bigRy_0.buffer instanceof ArrayBuffer && bigRy_0.BYTES_PER_ELEMENT === 1 && bigRy_0.length === 32)) {
          __compactRuntime.typeError('respond_bidirectional',
                                     'argument 5 (argument 6 as invoked from Typescript)',
                                     'signet-signer.compact line 226 char 1',
                                     'Bytes<32>',
                                     bigRy_0)
        }
        if (!(s_0.buffer instanceof ArrayBuffer && s_0.BYTES_PER_ELEMENT === 1 && s_0.length === 32)) {
          __compactRuntime.typeError('respond_bidirectional',
                                     'argument 6 (argument 7 as invoked from Typescript)',
                                     'signet-signer.compact line 226 char 1',
                                     'Bytes<32>',
                                     s_0)
        }
        if (!(typeof(recoveryId_0) === 'bigint' && recoveryId_0 >= 0n && recoveryId_0 <= 255n)) {
          __compactRuntime.typeError('respond_bidirectional',
                                     'argument 7 (argument 8 as invoked from Typescript)',
                                     'signet-signer.compact line 226 char 1',
                                     'Uint<0..256>',
                                     recoveryId_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(requestId_0).concat(_descriptor_1.toValue(serializedOutput_0).concat(_descriptor_2.toValue(outputLen_0).concat(_descriptor_0.toValue(bigRx_0).concat(_descriptor_0.toValue(bigRy_0).concat(_descriptor_0.toValue(s_0).concat(_descriptor_2.toValue(recoveryId_0))))))),
            alignment: _descriptor_0.alignment().concat(_descriptor_1.alignment().concat(_descriptor_2.alignment().concat(_descriptor_0.alignment().concat(_descriptor_0.alignment().concat(_descriptor_0.alignment().concat(_descriptor_2.alignment()))))))
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._respond_bidirectional_0(context,
                                                             partialProofData,
                                                             requestId_0,
                                                             serializedOutput_0,
                                                             outputLen_0,
                                                             bigRx_0,
                                                             bigRy_0,
                                                             s_0,
                                                             recoveryId_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      }
    };
    this.impureCircuits = {
      sign: this.circuits.sign,
      sign_bidirectional: this.circuits.sign_bidirectional,
      respond: this.circuits.respond,
      respond_bidirectional: this.circuits.respond_bidirectional
    };
    this.provableCircuits = {
      sign: this.circuits.sign,
      sign_bidirectional: this.circuits.sign_bidirectional,
      respond: this.circuits.respond,
      respond_bidirectional: this.circuits.respond_bidirectional
    };
  }
  async initialState(...args_0) {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`Contract state constructor: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const constructorContext_0 = args_0[0];
    if (typeof(constructorContext_0) !== 'object') {
      throw new __compactRuntime.CompactError(`Contract state constructor: expected 'constructorContext' in argument 1 (as invoked from Typescript) to be an object`);
    }
    if (!('initialPrivateState' in constructorContext_0)) {
      throw new __compactRuntime.CompactError(`Contract state constructor: expected 'initialPrivateState' in argument 1 (as invoked from Typescript)`);
    }
    if (!('initialZswapLocalState' in constructorContext_0)) {
      throw new __compactRuntime.CompactError(`Contract state constructor: expected 'initialZswapLocalState' in argument 1 (as invoked from Typescript)`);
    }
    if (typeof(constructorContext_0.initialZswapLocalState) !== 'object') {
      throw new __compactRuntime.CompactError(`Contract state constructor: expected 'initialZswapLocalState' in argument 1 (as invoked from Typescript) to be an object`);
    }
    const state_0 = new __compactRuntime.ContractState();
    let stateValue_0 = __compactRuntime.StateValue.newArray();
    stateValue_0 = stateValue_0.arrayPush(__compactRuntime.StateValue.newNull());
    state_0.data = new __compactRuntime.ChargedState(stateValue_0);
    state_0.setOperation('sign', new __compactRuntime.ContractOperation());
    state_0.setOperation('sign_bidirectional', new __compactRuntime.ContractOperation());
    state_0.setOperation('respond', new __compactRuntime.ContractOperation());
    state_0.setOperation('respond_bidirectional', new __compactRuntime.ContractOperation());
    const context = __compactRuntime.createCircuitContext('constructor', __compactRuntime.dummyContractAddress(), constructorContext_0.initialZswapLocalState.coinPublicKey, state_0.data, constructorContext_0.initialPrivateState);
    const partialProofData = {
      input: { value: [], alignment: [] },
      output: undefined,
      publicTranscript: [],
      privateTranscriptOutputs: []
    };
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_2.toValue(0n),
                                                                                              alignment: _descriptor_2.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_4.toValue(0n),
                                                                                              alignment: _descriptor_4.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } }]);
    state_0.data = new __compactRuntime.ChargedState(context.callContext.currentQueryContext.state.state);
    return {
      currentContractState: state_0,
      currentPrivateState: context.callContext.currentPrivateState,
      currentZswapLocalState: context.callContext.currentZswapLocalState
    }
  }
  _persistentHash_0(value_0) {
    const result_0 = __compactRuntime.persistentHash(_descriptor_11, value_0);
    return result_0;
  }
  _persistentHash_1(value_0) {
    const result_0 = __compactRuntime.persistentHash(_descriptor_23, value_0);
    return result_0;
  }
  _persistentHash_2(value_0) {
    const result_0 = __compactRuntime.persistentHash(_descriptor_21, value_0);
    return result_0;
  }
  _serialize_0(value_0) {
    return Uint8Array.from([...Array.from(__compactRuntime.convertBigintToBytes(8,
                                                                                value_0.nonce,
                                                                                '<standard library>'),
                                          BigInt),
                            ...Array.from(value_0.commitment, BigInt),
                            ...Array.from(value_0.payload, BigInt),
                            ...Array.from(__compactRuntime.convertBigintToBytes(4,
                                                                                value_0.keyVersion,
                                                                                '<standard library>'),
                                          BigInt),
                            ...Array.from(value_0.algo, BigInt),
                            ...Array.from(value_0.dest, BigInt),
                            ...Array.from(value_0.params, BigInt),
                            ...Array.from(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                                          BigInt)],
                           Number);
  }
  _serialize_1(value_0) {
    return Uint8Array.from([...Array.from(__compactRuntime.convertBigintToBytes(8,
                                                                                value_0.nonce,
                                                                                '<standard library>'),
                                          BigInt),
                            ...Array.from(value_0.commitment, BigInt),
                            ...Array.from(__compactRuntime.convertBigintToBytes(4,
                                                                                value_0.keyVersion,
                                                                                '<standard library>'),
                                          BigInt),
                            ...Array.from(value_0.caip2Id, BigInt),
                            ...Array.from(value_0.dest, BigInt),
                            ...Array.from(value_0.params, BigInt),
                            ...Array.from(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                                          BigInt)],
                           Number);
  }
  _serialize_2(value_0) {
    return Uint8Array.from([...Array.from(value_0.evmTo, BigInt),
                            ...Array.from(__compactRuntime.convertBigintToBytes(8,
                                                                                value_0.evmChainId,
                                                                                '<standard library>'),
                                          BigInt),
                            ...Array.from(__compactRuntime.convertBigintToBytes(8,
                                                                                value_0.evmNonce,
                                                                                '<standard library>'),
                                          BigInt),
                            ...Array.from(__compactRuntime.convertBigintToBytes(8,
                                                                                value_0.evmGasLimit,
                                                                                '<standard library>'),
                                          BigInt),
                            ...Array.from(__compactRuntime.convertBigintToBytes(16,
                                                                                value_0.evmMaxFee,
                                                                                '<standard library>'),
                                          BigInt),
                            ...Array.from(__compactRuntime.convertBigintToBytes(16,
                                                                                value_0.evmPriorityFee,
                                                                                '<standard library>'),
                                          BigInt),
                            ...Array.from(__compactRuntime.convertBigintToBytes(16,
                                                                                value_0.evmValue,
                                                                                '<standard library>'),
                                          BigInt),
                            value_0.argCount,
                            ...Array.from(value_0.funcSig, BigInt),
                            ...Array.from(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                                          BigInt)],
                           Number);
  }
  _serialize_3(value_0) {
    const t_0 = value_0.args;
    return Uint8Array.from([...Array.from(t_0[0], BigInt),
                            ...Array.from(t_0[1], BigInt),
                            ...Array.from(t_0[2], BigInt),
                            ...Array.from(t_0[3], BigInt),
                            ...Array.from(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                                          BigInt)],
                           Number);
  }
  _serialize_4(value_0) {
    return Uint8Array.from([...Array.from(value_0.outputSchema, BigInt),
                            ...Array.from(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                                          BigInt)],
                           Number);
  }
  _serialize_5(value_0) {
    return Uint8Array.from([...Array.from(value_0.respondSchema, BigInt),
                            ...Array.from(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                                          BigInt)],
                           Number);
  }
  _serialize_6(value_0) {
    return Uint8Array.from([...Array.from(value_0.serializedOutput, BigInt),
                            value_0.outputLen,
                            ...Array.from(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                                          BigInt)],
                           Number);
  }
  _serialize_7(value_0) {
    return Uint8Array.from([...Array.from(value_0.bigRx, BigInt),
                            ...Array.from(value_0.bigRy, BigInt),
                            ...Array.from(value_0.s, BigInt),
                            value_0.recoveryId,
                            ...Array.from(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                                          BigInt)],
                           Number);
  }
  _serialize_8(value_0) {
    return Uint8Array.from([...Array.from(value_0.requestId, BigInt),
                            ...Array.from(value_0.tail, BigInt)],
                           Number);
  }
  _callerSecretKey_0(context, partialProofData) {
    const witnessContext_0 = __compactRuntime.createWitnessContext(ledger(context.callContext.currentQueryContext.state), context.callContext.currentPrivateState, context.callContext.currentQueryContext.address);
    const [nextPrivateState_0, result_0] = this.witnesses.callerSecretKey(witnessContext_0);
    context.callContext.currentPrivateState = nextPrivateState_0;
    if (!(result_0.buffer instanceof ArrayBuffer && result_0.BYTES_PER_ELEMENT === 1 && result_0.length === 32)) {
      __compactRuntime.typeError('callerSecretKey',
                                 'return value',
                                 'signet-signer.compact line 39 char 1',
                                 'Bytes<32>',
                                 result_0)
    }
    partialProofData.privateTranscriptOutputs.push({
      value: _descriptor_0.toValue(result_0),
      alignment: _descriptor_0.alignment()
    });
    return result_0;
  }
  _userCommitment_0(sk_0) {
    return this._persistentHash_1([new Uint8Array([115, 105, 103, 110, 101, 114, 58, 117, 115, 101, 114, 58, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                                   sk_0]);
  }
  async _emitPart_0(context, partialProofData, name_0, requestId_0, tail_0) {
    let t_0;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newArray()
                                                          .arrayPush(__compactRuntime.StateValue.newCell({ value: _descriptor_9.toValue(1n),
                                                                                                           alignment: _descriptor_9.alignment() })).arrayPush(__compactRuntime.StateValue.newCell({ value: _descriptor_2.toValue(10n),
                                                                                                                                                                                                    alignment: _descriptor_2.alignment() })).arrayPush(__compactRuntime.StateValue.newCell({ value: _descriptor_10.toValue((t_0 = { name:
                                                                                                                                                                                                                                                                                                                                      name_0,
                                                                                                                                                                                                                                                                                                                                    payload:
                                                                                                                                                                                                                                                                                                                                      this._serialize_8({ requestId:
                                                                                                                                                                                                                                                                                                                                                            requestId_0,
                                                                                                                                                                                                                                                                                                                                                          tail:
                                                                                                                                                                                                                                                                                                                                                            tail_0 }) },
                                                                                                                                                                                                                                                                                                                            Uint8Array.from([...Array.from(t_0.name,
                                                                                                                                                                                                                                                                                                                                                           BigInt),
                                                                                                                                                                                                                                                                                                                                             ...Array.from(t_0.payload,
                                                                                                                                                                                                                                                                                                                                                           BigInt)],
                                                                                                                                                                                                                                                                                                                                            Number))),
                                                                                                                                                                                                                                                                                             alignment: _descriptor_10.alignment() }))
                                                          .encode() } },
                                       'log']);
    return [];
  }
  async _sign_0(context, partialProofData, payload_0, keyVersion_0) {
    const commitment_0 = this._userCommitment_0(this._callerSecretKey_0(context,
                                                                        partialProofData));
    const nonceValue_0 = _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                   partialProofData,
                                                                                   [
                                                                                    { dup: { n: 0 } },
                                                                                    { idx: { cached: false,
                                                                                             pushPath: false,
                                                                                             path: [
                                                                                                    { tag: 'value',
                                                                                                      value: { value: _descriptor_2.toValue(0n),
                                                                                                               alignment: _descriptor_2.alignment() } }] } },
                                                                                    { popeq: { cached: true,
                                                                                               result: undefined } }]).value);
    const tmp_0 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_2.toValue(0n),
                                                                  alignment: _descriptor_2.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_3.toValue(tmp_0),
                                                                alignment: _descriptor_3.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 1 } }]);
    const tail_0 = this._serialize_0({ nonce: nonceValue_0,
                                       commitment: commitment_0,
                                       payload: payload_0,
                                       keyVersion: keyVersion_0,
                                       algo: new Uint8Array(32),
                                       dest: new Uint8Array(32),
                                       params: new Uint8Array(64) });
    const requestId_0 = this._persistentHash_0(tail_0);
    await this._emitPart_0(context,
                           partialProofData,
                           new Uint8Array([83, 71, 78, 49, 58, 83, 73, 71, 78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                           requestId_0,
                           tail_0);
    return [];
  }
  async _sign_bidirectional_0(context,
                              partialProofData,
                              evmTo_0,
                              evmChainId_0,
                              evmNonce_0,
                              evmGasLimit_0,
                              evmMaxFee_0,
                              evmPriorityFee_0,
                              evmValue_0,
                              funcSig_0,
                              args_0,
                              argCount_0,
                              caip2Id_0,
                              keyVersion_0,
                              dest_0,
                              params_0,
                              outputSchema_0,
                              respondSchema_0)
  {
    const commitment_0 = this._userCommitment_0(this._callerSecretKey_0(context,
                                                                        partialProofData));
    const nonceValue_0 = _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                   partialProofData,
                                                                                   [
                                                                                    { dup: { n: 0 } },
                                                                                    { idx: { cached: false,
                                                                                             pushPath: false,
                                                                                             path: [
                                                                                                    { tag: 'value',
                                                                                                      value: { value: _descriptor_2.toValue(0n),
                                                                                                               alignment: _descriptor_2.alignment() } }] } },
                                                                                    { popeq: { cached: true,
                                                                                               result: undefined } }]).value);
    const tmp_0 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_2.toValue(0n),
                                                                  alignment: _descriptor_2.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_3.toValue(tmp_0),
                                                                alignment: _descriptor_3.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 1 } }]);
    const t1_0 = this._serialize_1({ nonce: nonceValue_0,
                                     commitment: commitment_0,
                                     keyVersion: keyVersion_0,
                                     caip2Id: caip2Id_0,
                                     dest: dest_0,
                                     params: params_0 });
    const t2_0 = this._serialize_2({ evmTo: evmTo_0,
                                     evmChainId: evmChainId_0,
                                     evmNonce: evmNonce_0,
                                     evmGasLimit: evmGasLimit_0,
                                     evmMaxFee: evmMaxFee_0,
                                     evmPriorityFee: evmPriorityFee_0,
                                     evmValue: evmValue_0,
                                     argCount: argCount_0,
                                     funcSig: funcSig_0 });
    const t3_0 = this._serialize_3({ args: args_0 });
    const t4_0 = this._serialize_4({ outputSchema: outputSchema_0 });
    const t5_0 = this._serialize_5({ respondSchema: respondSchema_0 });
    const requestId_0 = this._persistentHash_2([t1_0, t2_0, t3_0, t4_0, t5_0]);
    await this._emitPart_0(context,
                           partialProofData,
                           new Uint8Array([83, 71, 78, 49, 58, 83, 73, 71, 78, 66, 73, 58, 49, 47, 53, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                           requestId_0,
                           t1_0);
    await this._emitPart_0(context,
                           partialProofData,
                           new Uint8Array([83, 71, 78, 49, 58, 83, 73, 71, 78, 66, 73, 58, 50, 47, 53, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                           requestId_0,
                           t2_0);
    await this._emitPart_0(context,
                           partialProofData,
                           new Uint8Array([83, 71, 78, 49, 58, 83, 73, 71, 78, 66, 73, 58, 51, 47, 53, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                           requestId_0,
                           t3_0);
    await this._emitPart_0(context,
                           partialProofData,
                           new Uint8Array([83, 71, 78, 49, 58, 83, 73, 71, 78, 66, 73, 58, 52, 47, 53, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                           requestId_0,
                           t4_0);
    await this._emitPart_0(context,
                           partialProofData,
                           new Uint8Array([83, 71, 78, 49, 58, 83, 73, 71, 78, 66, 73, 58, 53, 47, 53, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                           requestId_0,
                           t5_0);
    return [];
  }
  async _respond_0(context,
                   partialProofData,
                   requestId_0,
                   bigRx_0,
                   bigRy_0,
                   s_0,
                   recoveryId_0)
  {
    const tail_0 = this._serialize_7({ bigRx: bigRx_0,
                                       bigRy: bigRy_0,
                                       s: s_0,
                                       recoveryId: recoveryId_0 });
    await this._emitPart_0(context,
                           partialProofData,
                           new Uint8Array([83, 71, 78, 49, 58, 82, 69, 83, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                           requestId_0,
                           tail_0);
    return [];
  }
  async _respond_bidirectional_0(context,
                                 partialProofData,
                                 requestId_0,
                                 serializedOutput_0,
                                 outputLen_0,
                                 bigRx_0,
                                 bigRy_0,
                                 s_0,
                                 recoveryId_0)
  {
    const rid_0 = requestId_0;
    const t1_0 = this._serialize_6({ serializedOutput: serializedOutput_0,
                                     outputLen: outputLen_0 });
    const t2_0 = this._serialize_7({ bigRx: bigRx_0,
                                     bigRy: bigRy_0,
                                     s: s_0,
                                     recoveryId: recoveryId_0 });
    await this._emitPart_0(context,
                           partialProofData,
                           new Uint8Array([83, 71, 78, 49, 58, 82, 69, 83, 80, 66, 73, 58, 49, 47, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                           rid_0,
                           t1_0);
    await this._emitPart_0(context,
                           partialProofData,
                           new Uint8Array([83, 71, 78, 49, 58, 82, 69, 83, 80, 66, 73, 58, 50, 47, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                           rid_0,
                           t2_0);
    return [];
  }
}
export function ledger(stateOrChargedState) {
  const state = stateOrChargedState instanceof __compactRuntime.StateValue ? stateOrChargedState : stateOrChargedState.state;
  const chargedState = stateOrChargedState instanceof __compactRuntime.StateValue ? new __compactRuntime.ChargedState(stateOrChargedState) : stateOrChargedState;
  const context = {
    callContext: { currentQueryContext: new __compactRuntime.QueryContext(chargedState, __compactRuntime.dummyContractAddress()), currentGasCost: __compactRuntime.emptyRunningCost() },
    costModel: __compactRuntime.CostModel.initialCostModel()
  };
  const partialProofData = {
    input: { value: [], alignment: [] },
    output: undefined,
    publicTranscript: [],
    privateTranscriptOutputs: []
  };
  return {
    get signetNonce() {
      return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                       partialProofData,
                                                                       [
                                                                        { dup: { n: 0 } },
                                                                        { idx: { cached: false,
                                                                                 pushPath: false,
                                                                                 path: [
                                                                                        { tag: 'value',
                                                                                          value: { value: _descriptor_2.toValue(0n),
                                                                                                   alignment: _descriptor_2.alignment() } }] } },
                                                                        { popeq: { cached: true,
                                                                                   result: undefined } }]).value);
    }
  };
}
const _emptyContext = {
  callContext: { currentQueryContext: new __compactRuntime.QueryContext(new __compactRuntime.ContractState().data, __compactRuntime.dummyContractAddress()), currentGasCost: __compactRuntime.emptyRunningCost() }
};
const _dummyContract = new Contract({
  callerSecretKey: (...args) => undefined
});
export const pureCircuits = {};
export const contractReferenceLocations =
  { tag: 'publicLedgerArray', indices: { } };
export const expectedVk = {
  'respond': 'e9e3845de51583e700cde53d5dc5f5a3cd3a1213dd2b568b9a3b3d1334af7ff9',
  'respond_bidirectional': '2333d2628afd6d24a7763599a798fb3f490279122b0c5431014d0e4164eb52f2',
  'sign': '7025aef1aaed1ff18a8e92cb1375058c53e0c80ad855d37f7a3cedc1822dd8da',
  'sign_bidirectional': 'e654be5c83355acf3380982a70eebf4cb49de9ca898b29edb2b8186b00919756',
};

//# sourceMappingURL=index.js.map
