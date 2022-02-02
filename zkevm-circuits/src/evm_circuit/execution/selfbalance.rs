use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        table::{AccountFieldTag, CallContextFieldTag},
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use eth_types::ToScalar;
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct SelfbalanceGadget<F> {
    same_context: SameContextGadget<F>,
    caller_address: Cell<F>,
    self_balance: Cell<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for SelfbalanceGadget<F> {
    const NAME: &'static str = "SELFBALANCE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::SELFBALANCE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let caller_address = cb.query_cell();
        cb.call_context_lookup(
            None,
            CallContextFieldTag::CallerAddress,
            caller_address.expr(),
        );

        let self_balance = cb.query_cell();
        cb.account_read(
            caller_address.expr(),
            AccountFieldTag::Balance,
            self_balance.expr(),
        );

        cb.stack_push(self_balance.expr());

        let opcode = cb.query_cell();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(3.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition, None);

        Self {
            same_context,
            self_balance,
            caller_address,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction<F>,
        call: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        dbg!(tx.caller_address);
        dbg!(call.caller_address);

        self.caller_address
            .assign(region, offset, call.caller_address.to_scalar())?;

        let self_balance = block.rws[step.rw_indices[2]].stack_value();
        dbg!(&self_balance);
        self.self_balance
            .assign(region, offset, self_balance.to_scalar())?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        step::ExecutionState,
        table::{AccountFieldTag, CallContextFieldTag},
        test::run_test_circuit_incomplete_fixed_table,
        util::RandomLinearCombination,
        witness::{Block, BlockContext, Bytecode, Call, ExecStep, Rw, Transaction},
    };
    use bus_mapping::evm::OpcodeId;
    use eth_types::{address, bytecode, Address, ToLittleEndian, ToWord, Word};
    use halo2::arithmetic::BaseExt;
    use pairing::bn256::Fr;

    #[test]
    fn selfbalance_gadget_test() {
        let bytecode = Bytecode::new(
            bytecode! {
                #[start]
                SELFBALANCE
                STOP
            }
            .to_vec(),
        );
        // let self_balance = 5523425; // figure out how this is being set elswhere?
        let self_balance = 0usize;

        let caller_address = Address::zero();
        // address!("0x00000000000000000000000000000000c014ba5e");

        let tx_id = 0;
        let call_id = 1;

        let gas_left = vec![OpcodeId::SELFBALANCE, OpcodeId::STOP]
            .iter()
            .map(|o| o.constant_gas_cost().as_u64())
            .sum();

        let randomness = Fr::rand();
        let block = Block {
            randomness,
            txs: vec![Transaction {
                id: tx_id,
                caller_address,
                steps: vec![
                    ExecStep {
                        execution_state: ExecutionState::SELFBALANCE,
                        rw_indices: vec![0, 1, 2],
                        rw_counter: 1,
                        program_counter: 0,
                        stack_pointer: 1024,
                        gas_left,
                        gas_cost: OpcodeId::SELFBALANCE.constant_gas_cost().as_u64(),
                        opcode: Some(OpcodeId::SELFBALANCE),
                        ..Default::default()
                    },
                    ExecStep {
                        execution_state: ExecutionState::STOP,
                        rw_counter: 4,
                        program_counter: 1,
                        stack_pointer: 1023,
                        gas_left: 0,
                        opcode: Some(OpcodeId::STOP),
                        ..Default::default()
                    },
                ],
                calls: vec![Call {
                    id: 1,
                    is_root: true,
                    is_create: false,
                    caller_address,
                    opcode_source: RandomLinearCombination::random_linear_combine(
                        bytecode.hash.to_le_bytes(),
                        randomness,
                    ),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            rws: vec![
                Rw::CallContext {
                    call_id,
                    rw_counter: 1,
                    is_write: false,
                    field_tag: CallContextFieldTag::CallerAddress,
                    value: caller_address.to_word(),
                },
                Rw::Account {
                    rw_counter: 2,
                    is_write: false,
                    account_address: caller_address,
                    field_tag: AccountFieldTag::Balance,
                    value: Word::from(self_balance),
                    value_prev: Word::from(self_balance),
                },
                Rw::Stack {
                    call_id,
                    rw_counter: 3,
                    is_write: true,
                    stack_pointer: 1023,
                    value: Word::from(self_balance),
                },
            ],
            bytecodes: vec![bytecode],
            context: BlockContext {
                coinbase: address!("0x00000000000000000000000000000000c014ba5e"),
                // time: 1633398551,
                ..Default::default()
            },
            ..Default::default()
        };

        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
        // called this: let prover =
        //     MockProver::<F>::run(k, &circuit, power_of_randomness).unwrap();
        // prover.verify()

        // the other one ends up calling pub fn run_test_circuits_with_config(
    }
}
