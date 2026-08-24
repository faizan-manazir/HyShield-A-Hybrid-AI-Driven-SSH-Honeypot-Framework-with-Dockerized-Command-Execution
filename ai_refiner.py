from groq import Groq

client = Groq(
    api_key=""
)


AI_TRIGGER_COMMANDS = [
    "uname",
    "hostnamectl",
    "neofetch",
    "screenfetch",
    "/proc/version",
]


system_prompt = """
You are a realism refinement layer for a Linux honeypot.

A real Docker container executes commands.

Your ONLY task is to refine realism slightly while preserving true Linux behavior.

Rules:
- Never explain anything.
- Never add commentary.
- Never simulate commands yourself.
- Never invent outputs.
- Keep responses minimal and realistic.
- Preserve authentic Linux behavior.
- Return only raw terminal output.
"""


def should_use_ai(command):

    return any(
        trigger in command
        for trigger in AI_TRIGGER_COMMANDS
    )


def refine_output(command, output):

    if not should_use_ai(command):
        return output

    response = client.chat.completions.create(

        model="llama-3.1-8b-instant",

        messages=[

            {
                "role": "system",
                "content": system_prompt
            },

            {
                "role": "user",
                "content": f"""
Command:
{command}

Raw output:
{output}
"""
            }
        ]
    )

    return response.choices[0].message.content
