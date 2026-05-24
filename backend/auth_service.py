from flask import session


MAX_FAILED_ATTEMPTS = 5


class AuthService:
    def __init__(self, user_repository):
        self.user_repository = user_repository

    def authenticate(self, username, password):
        username = (username or "").strip()
        password = password or ""
        if not username or not password:
            return None

        user = self.user_repository.get_user_by_username(username)
        if not user:
            return None

        if not user["is_active"] or user["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
            return None

        if not self.user_repository.verify_password(user, password):
            self.user_repository.increment_failed_attempts(username)
            return None

        self.user_repository.reset_failed_attempts(username)
        self.user_repository.update_last_login(username)
        user["failed_attempts"] = 0
        return user

    def create_session(self, user):
        session.clear()
        session.permanent = True
        session["username"] = user["username"]
        session["role"] = user["role"]

    def clear_session(self):
        session.clear()

    def get_current_user(self):
        username = session.get("username")
        role = session.get("role")
        if not username or not role:
            return None
        return {"username": username, "role": role}
