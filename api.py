from docker_executor import execute_command

from sanitizer import sanitize_output

from ai_refiner import refine_output


def process_command(command):

    raw_output = execute_command(
        command
    )

    clean_output = sanitize_output(
        raw_output
    )

    final_output = refine_output(
        command,
        clean_output
    )

    return final_output
