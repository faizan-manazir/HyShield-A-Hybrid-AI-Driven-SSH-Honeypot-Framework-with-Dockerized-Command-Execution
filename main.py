from docker_executor import DockerExecutor
from sanitizer import sanitize_output
from ai_refiner import refine_output

executor = DockerExecutor()

while True:
    try:
        command = input("root@web-prod-01:~$ ").strip()

        if not command:
            continue

        raw_output = executor.execute(command)
        clean_output = sanitize_output(raw_output)
        final_output = refine_output(command, clean_output)

        if final_output.strip():
            print(final_output)

    except KeyboardInterrupt:
        print("\nlogout")
        break

    except EOFError:
        print("\nlogout")
        break
