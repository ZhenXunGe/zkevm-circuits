use std::convert::TryInto;

use eth_types::ToLittleEndian;
use halo2::{
    arithmetic::FieldExt,
    plonk::{Error, Expression},
};

use crate::{
    evm_circuit::{
        param::{N_BYTES_MEMORY_ADDRESS, N_BYTES_WORD},
        step::ExecutionState,
        table::{CallContextFieldTag, TxContextFieldTag},
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition},
            memory_gadget::BufferReaderGadget,
            Cell, MemoryAddress, RandomLinearCombination,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};

use super::ExecutionGadget;

#[derive(Clone, Debug)]
pub(crate) struct CallDataLoadGadget<F> {
    /// Gadget to constrain the same context.
    same_context: SameContextGadget<F>,
    /// Transaction id from the tx context.
    tx_id: Cell<F>,
    /// The bytes offset in calldata, from which we load a 32-bytes word.
    calldata_start: MemoryAddress<F>,
    /// Start reading into buffer from this source address.
    src_addr: Cell<F>,
    /// End of the source address.
    src_addr_end: Cell<F>,
    /// Gadget to read from tx calldata, which we validate against the word
    /// pushed to stack.
    buffer_reader: BufferReaderGadget<F, N_BYTES_WORD, N_BYTES_MEMORY_ADDRESS>,
}

impl<F: FieldExt> ExecutionGadget<F> for CallDataLoadGadget<F> {
    const EXECUTION_STATE: ExecutionState = ExecutionState::CALLDATALOAD;

    const NAME: &'static str = "CALLDATALOAD";

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let calldata_start = cb.query_rlc();

        // Pop the offset value from stack.
        cb.stack_pop(calldata_start.expr());

        // Add a lookup constrain for TxId in the RW table.
        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);

        let src_addr = cb.query_cell();
        let src_addr_end = cb.query_cell();
        let buffer_reader = BufferReaderGadget::construct(cb, &src_addr, &src_addr_end);

        let mut calldata_word = (0..N_BYTES_WORD)
            .map(|idx| {
                cb.condition(buffer_reader.read_flag(idx), |cb| {
                    cb.tx_context_lookup(
                        tx_id.expr(),
                        TxContextFieldTag::CallData,
                        Some(calldata_start.expr() + idx.expr()),
                        buffer_reader.byte(idx),
                    );
                });
                buffer_reader.byte(idx)
            })
            .collect::<Vec<Expression<F>>>();

        // Since the stack items are in little endian form, we reverse the bytes
        // here.
        calldata_word.reverse();

        // Add a lookup constraint for the 32-bytes that should have been pushed
        // to the stack.
        let calldata_word: [Expression<F>; N_BYTES_WORD] = calldata_word.try_into().unwrap();
        cb.stack_push(RandomLinearCombination::random_linear_combine_expr(
            calldata_word,
            cb.power_of_randomness(),
        ));

        let step_state_transition = StepStateTransition {
            rw_counter: Transition::Delta(3.expr()),
            program_counter: Transition::Delta(1.expr()),
            stack_pointer: Transition::Delta(0.expr()),
            ..Default::default()
        };

        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition, None);

        Self {
            same_context,
            calldata_start,
            src_addr,
            src_addr_end,
            tx_id,
            buffer_reader,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut halo2::circuit::Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction,
        _call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        // set the value for bytes offset in calldata. This is where we start
        // reading bytes from.
        let calldata_offset = block.rws[step.rw_indices[0]].stack_value();

        // assign the calldata start and end cells.
        self.calldata_start.assign(
            region,
            offset,
            Some(
                calldata_offset.to_le_bytes()[..N_BYTES_MEMORY_ADDRESS]
                    .try_into()
                    .unwrap(),
            ),
        )?;

        // assign the tx id.
        self.tx_id
            .assign(region, offset, Some(F::from(tx.id as u64)))?;

        // assign to the buffer reader gadget.
        let src_addr = calldata_offset.as_usize();
        let src_addr_end = tx.call_data.len().min(src_addr + N_BYTES_WORD);
        self.src_addr
            .assign(region, offset, Some(F::from(src_addr as u64)))?;
        self.src_addr_end
            .assign(region, offset, Some(F::from(src_addr_end as u64)))?;
        let mut calldata_bytes = vec![0u8; N_BYTES_WORD];
        for (i, byte) in calldata_bytes.iter_mut().enumerate() {
            if src_addr + i < tx.call_data_length {
                *byte = tx.call_data[src_addr + i];
            }
        }
        self.buffer_reader.assign(
            region,
            offset,
            src_addr as u64,
            src_addr_end as u64,
            &calldata_bytes,
            &[1u8; N_BYTES_WORD],
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use bus_mapping::evm::OpcodeId;
    use eth_types::{bytecode, Word};
    use halo2::arithmetic::BaseExt;
    use pairing::bn256::Fr;

    use crate::evm_circuit::{
        step::ExecutionState,
        table::{CallContextFieldTag, RwTableTag},
        test::run_test_circuit_incomplete_fixed_table,
        witness::{Block, Bytecode, Call, CodeSource, ExecStep, Rw, RwMap, Transaction},
    };

    fn test_ok(call_data: Vec<u8>, calldata_offset: Word, expected: Word) {
        let randomness = Fr::rand();
        let bytecode = bytecode! {
            #[start]
            PUSH32(calldata_offset)
            CALLDATALOAD
            STOP
        };
        let bytecode = Bytecode::new(bytecode.to_vec());
        let tx_id = 1;
        let call_id = 1;
        let call_data_length = call_data.len();

        let rws_stack = vec![
            Rw::Stack {
                rw_counter: 1,
                is_write: true,
                call_id,
                stack_pointer: 1023,
                value: calldata_offset,
            },
            Rw::Stack {
                rw_counter: 2,
                is_write: false,
                call_id,
                stack_pointer: 1023,
                value: calldata_offset,
            },
            Rw::Stack {
                rw_counter: 4,
                is_write: true,
                call_id,
                stack_pointer: 1023,
                value: expected,
            },
        ];
        let rws_call_context = vec![Rw::CallContext {
            rw_counter: 3,
            is_write: false,
            call_id,
            field_tag: CallContextFieldTag::TxId,
            value: Word::one(),
        }];
        let mut rws_map = HashMap::new();
        rws_map.insert(RwTableTag::Stack, rws_stack);
        rws_map.insert(RwTableTag::CallContext, rws_call_context);

        let gas_left = vec![OpcodeId::PUSH32, OpcodeId::CALLDATALOAD, OpcodeId::STOP]
            .iter()
            .map(|o| o.constant_gas_cost().as_u64())
            .sum();
        let steps = vec![
            ExecStep {
                execution_state: ExecutionState::PUSH,
                rw_indices: vec![(RwTableTag::Stack, 0)],
                rw_counter: 1,
                program_counter: 0,
                stack_pointer: 1024,
                gas_left,
                gas_cost: OpcodeId::PUSH32.constant_gas_cost().as_u64(),
                opcode: Some(OpcodeId::PUSH32),
                ..Default::default()
            },
            ExecStep {
                execution_state: ExecutionState::CALLDATALOAD,
                rw_indices: vec![
                    (RwTableTag::Stack, 1),
                    (RwTableTag::CallContext, 0),
                    (RwTableTag::Stack, 2),
                ],
                rw_counter: 2,
                program_counter: 33,
                stack_pointer: 1023,
                gas_left: gas_left - OpcodeId::PUSH32.constant_gas_cost().as_u64(),
                gas_cost: OpcodeId::CALLDATALOAD.constant_gas_cost().as_u64(),
                opcode: Some(OpcodeId::CALLDATALOAD),
                ..Default::default()
            },
            ExecStep {
                execution_state: ExecutionState::STOP,
                rw_counter: 5,
                program_counter: 34,
                stack_pointer: 1023,
                gas_left: 0,
                opcode: Some(OpcodeId::STOP),
                ..Default::default()
            },
        ];

        let block = Block {
            randomness,
            txs: vec![Transaction {
                id: tx_id,
                call_data,
                call_data_length,
                steps,
                calls: vec![Call {
                    id: call_id,
                    is_root: true,
                    is_create: false,
                    call_data_length: call_data_length as u64,
                    code_source: CodeSource::Account(bytecode.hash),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            rws: RwMap(rws_map),
            bytecodes: vec![bytecode],
            ..Default::default()
        };

        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn calldataload_gadget_simple() {
        let bytes_from_hex = |s: &str| -> Vec<u8> { hex::decode(s).expect("invalid hex") };
        let word_from_hex = |s: &str| -> Word { Word::from_big_endian(&bytes_from_hex(s)) };

        let test_data: Vec<(Vec<u8>, usize, Word)> = vec![
            (
                bytes_from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEE"),
                0,
                word_from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEE"),
            ),
            (
                bytes_from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
                31,
                word_from_hex("FF00000000000000000000000000000000000000000000000000000000000000"),
            ),
            (
                bytes_from_hex("a1bacf5488bfafc33bad736db41f06866eaeb35e1c1dd81dfc268357ec98563f"),
                16,
                word_from_hex("6eaeb35e1c1dd81dfc268357ec98563f00000000000000000000000000000000"),
            ),
        ];

        test_data
            .iter()
            .for_each(|t| test_ok(t.0.clone(), Word::from(t.1), t.2));
    }
}
