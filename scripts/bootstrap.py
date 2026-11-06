"""Create private local configuration from examples without overwriting files."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    pairs = [('apps/lovelylivelog/.env.example', 'apps/lovelylivelog/.env'),
             ('apps/lovelylog/config.example.json', 'apps/lovelylog/config.local.json')]
    for source, target in pairs:
        destination = ROOT / target
        try:
            with destination.open('x', encoding='utf-8', newline='\n') as stream:
                stream.write((ROOT / source).read_text(encoding='utf-8'))
            print('Created:', target)
        except FileExistsError:
            print('Kept existing:', target)
    print('Fill your panel endpoint/key and log path before starting. Keep local mode for initial validation.')


if __name__ == '__main__':
    main()
