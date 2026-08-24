class ShellState:

    def __init__(self):

        self.current_directory = "/"

        self.history = []

        self.environment = {
            "USER": "root",
            "HOME": "/root",
            "HOSTNAME": "edge-gw-prod-01",
            "PWD": "/",
        }

    def update_directory(self, path):

        self.current_directory = path
        self.environment["PWD"] = path

    def add_history(self, command):

        self.history.append(command)


state = ShellState()
