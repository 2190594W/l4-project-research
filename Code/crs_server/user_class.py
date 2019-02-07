"""
User Class for flask_login package
"""

#pylint: disable=E0401
from flask_login import UserMixin

class User(UserMixin):
    """User class for login framework.

    Parameters
    ----------
    username : string
        String representing the user's `username`.
    id : UUID
        UUID representing the user's `id`.
    attrs : dict
        Dictionary representing the user's `attrs`.
    user_key : Bytes
        Bytes representing the user's `user_key`.
    active : boolean
        Boolean representing if the user is `active`.

    Attributes
    ----------
    username
    id
    attrs
    user_key
    active

    """
    #pylint: disable=R0913,W0622,C0103
    def __init__(self, id, username, attrs, user_key, active=True):
        self.id = id
        self.username = username
        self.attrs = attrs.replace("|", "\n")
        self.user_key = user_key
        self.active = active

    def is_active(self):
        """Returns if the user is active or not.

        Parameters
        ----------


        Returns
        -------
        boolean
            Returns True/False if the user is active/deactive.

        """
        # Here you should write whatever the code is
        # that checks the database if your user is active
        return self.active

    def activate(self):
        """Activates the user.

        Parameters
        ----------

        Returns
        -------

        """
        # Here you should write whatever the code is
        # that checks the database if your user is active
        self.active = True

    def deactivate(self):
        """Deactivates the user.

        Parameters
        ----------

        Returns
        -------

        """
        # Here you should write whatever the code is
        # that checks the database if your user is active
        self.active = False

    @classmethod
    def is_anonymous(cls):
        """Returns if the user is anonymous.

        Parameters
        ----------
        cls : User
            The User class object, `cls`.

        Returns
        -------
        boolean
            Returns True/False if the user is anonymous or not.

        """
        return False

    @classmethod
    def is_authenticated(cls):
        """Returns if the user is authenticated.

        Parameters
        ----------
        cls : User
            The User class object, `cls`.

        Returns
        -------
        boolean
            Returns True/False if the user is authenticated or not.

        """
        return True

    def set_user_key(self, user_key):
        """Sets the user's key.

        Parameters
        ----------
        Bytes
            Bytes representing the user's key.

        Returns
        -------


        """
        self.user_key = user_key

    def get_user_key(self):
        """Returns the user's key.

        Parameters
        ----------


        Returns
        -------
        Bytes
            Bytes representing the user's key.

        """
        return self.user_key

    def get_attrs(self):
        """Returns the user's attributes.

        Parameters
        ----------


        Returns
        -------
        Dict
            Dictionary representing the user's attributes.

        """
        return self.attrs
