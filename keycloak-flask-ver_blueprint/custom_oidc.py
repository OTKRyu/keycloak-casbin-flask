from flask_oidc import OpenIDConnect

class Custom_Oidc(OpenIDConnect):
    _oidc = None

    @classmethod
    def get_oidc(cls, app=None):
        if cls._oidc is None:
            if app is None:
                raise 'not enough arguments'
            oidc = OpenIDConnect(app)
            cls._oidc = oidc
        return cls._oidc