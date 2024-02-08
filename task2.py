import argparse
import boto3
import docker
import sys
import time

def run_command_in_docker(container, command):
    exec_id = container.exec_run(command, detach=True)
    exec_inspect = container.exec_inspect(exec_id.id)
    exec_output = exec_inspect['ExitCode']
    return exec_output

def send_logs_to_cloudwatch(log_group, log_stream, log_events, aws_access_key_id, aws_secret_access_key, aws_region):
    client = boto3.client(
        'logs',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=aws_region
    )

    try:
        response = client.describe_log_streams(logGroupName=log_group, logStreamNamePrefix=log_stream)
        if not response['logStreams']:
            client.create_log_stream(logGroupName=log_group, logStreamName=log_stream)

        log_events = [{'timestamp': int(time.time() * 1000), 'message': event} for event in log_events]

        response = client.put_log_events(
            logGroupName=log_group,
            logStreamName=log_stream,
            logEvents=log_events
        )

        print("Log events sent to CloudWatch successfully.")
    except client.exceptions.ResourceNotFoundException:
        print("The specified log group does not exist.")
    except client.exceptions.InvalidParameterException:
        print("The specified log stream name is invalid.")
    except client.exceptions.InvalidSequenceTokenException as e:
        print(f"Invalid sequence token: {e}")
        print("Retrieving the latest sequence token.")
        response = client.describe_log_streams(logGroupName=log_group, logStreamNamePrefix=log_stream)
        sequence_token = response['logStreams'][0]['uploadSequenceToken']
        response = client.put_log_events(
            logGroupName=log_group,
            logStreamName=log_stream,
            logEvents=log_events,
            sequenceToken=sequence_token
        )
        print("Log events sent to CloudWatch successfully.")
    except Exception as e:
        print(f"Error sending logs to CloudWatch: {str(e)}")


def main():
    parser = argparse.ArgumentParser(description='Run a command inside a Docker image and send logs to AWS CloudWatch.')
    parser.add_argument('--docker-image', type=str, help='Name of the Docker image', required=True)
    parser.add_argument('--bash-command', type=str, help='Bash command to run inside the Docker image', required=True)
    parser.add_argument('--aws-cloudwatch-group', type=str, help='Name of the AWS CloudWatch group', required=True)
    parser.add_argument('--aws-cloudwatch-stream', type=str, help='Name of the AWS CloudWatch stream', required=True)
    parser.add_argument('--aws-access-key-id', type=str, help='AWS Access Key ID', required=True)
    parser.add_argument('--aws-secret-access-key', type=str, help='AWS Secret Access Key', required=True)
    parser.add_argument('--aws-region', type=str, help='AWS Region', required=True)

    args = parser.parse_args()

    try:
        docker_client = docker.from_env()
        container = docker_client.containers.run(args.docker_image, detach=True)
        exit_code = run_command_in_docker(container, args.bash_command)
        container_logs = container.logs().decode().split('\n')
        send_logs_to_cloudwatch(args.aws_cloudwatch_group, args.aws_cloudwatch_stream, container_logs,
                                args.aws_access_key_id, args.aws_secret_access_key, args.aws_region)
        container.remove(force=True)
    except KeyboardInterrupt:
        print("Program interrupted.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
