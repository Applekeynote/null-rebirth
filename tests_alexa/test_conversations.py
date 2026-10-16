import pytest
from alexa_sim import server

@pytest.fixture(autouse=True)
def clean_contexts():
    server.conversations.clear()
    yield
    server.conversations.clear()

def test_new_conversations_do_not_follow_global_latest_run():
    original=server.lab.latest
    server.lab.latest='run-'+'e'*32
    try:
        a=server.conversation_context('a'*32);b=server.conversation_context('b'*32)
        assert a is not b
        assert a['run_id']==b['run_id']==server.lab.recorded['run_id']
    finally:server.lab.latest=original

def test_confirmation_cannot_cross_conversations():
    a=server.conversation_context('a'*32);b=server.conversation_context('b'*32)
    a['pending']={'state':{'run_id':'run-'+'1'*32},'confirmation_id':'example-one-use'}
    with pytest.raises(ValueError):server.conversation_arguments(b,'confirm_recovery',{})
    assert a['pending'] is not None
    assert server.conversation_arguments(a,'confirm_recovery',{})['confirmation_id']=='example-one-use'
    with pytest.raises(ValueError):server.conversation_arguments(a,'confirm_recovery',{})

def test_stale_conversation_run_is_rejected():
    ctx=server.conversation_context('a'*32)
    with pytest.raises(ValueError):server.conversation_context('a'*32,'run-'+'f'*32)
    assert ctx['run_id']==server.lab.recorded['run_id']

@pytest.mark.parametrize('tool',['get_recovery_status','prepare_recovery','inspect_resume_gate'])
def test_run_arguments_are_bound_to_conversation(tool):
    ctx=server.conversation_context('a'*32)
    assert server.conversation_arguments(ctx,tool,{'run_id':'OTHER'})['run_id']==ctx['run_id']

@pytest.mark.parametrize('bad',['','../secret','a'*31,'A'*32,None])
def test_invalid_conversation_id_is_rejected(bad):
    with pytest.raises((ValueError,TypeError)):server.conversation_context(bad)
