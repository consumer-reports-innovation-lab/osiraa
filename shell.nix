{ pkgs ? import <nixpkgs> {} }:

with pkgs;
let
  myPython = python3.withPackages( pp: with pp; []);
in mkShell {
  packages= [
    myPython
    ansible
    docker-compose

    isort
    black
  ];
  shellHook = ''
    . venv/bin/activate

    export POSTGRES_NAME=postgres
    export POSTGRES_USER=postgres
    export POSTGRES_PASSWORD=postgres
    export POSTGRES_PORT=15432

    export DRP_AA_ID=OSIRAA_LOCAL_001
  '';
}
