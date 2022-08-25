from casbin import Enforcer
from casbin.persist.adapters import FileAdapter

class Custom_Enforcer(Enforcer):
    _enforcer = None

    @classmethod
    def get_enforcer(cls, model=None, policy=None):
        if cls._enforcer is None:
            if model is None or policy is None:
                raise 'not enough arguments'
            adapter = FileAdapter(policy)
            enforcer = Enforcer(model, adapter)
            cls._enforcer = enforcer
        return cls._enforcer