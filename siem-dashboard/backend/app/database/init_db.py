from app.database.connection import Base, engine
# Import models here to ensure they are registered with Base
from app.models import attacker, session, event, authentication, command, fingerprint, forensic, alert, environment

def init_db():
    Base.metadata.create_all(bind=engine)

if __name__ == "__main__":
    init_db()
    print("Database tables created.")
