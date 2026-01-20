program PFNetFilter;

uses
  Forms,
  samples_config in '..\include\samples_config.pas',
  ProtocolFiltersAPI in '..\include\ProtocolFiltersAPI.pas',
  NetFilter2API in '..\include\NetFilter2API.pas',
  MainUnit in 'MainUnit.pas' {Form1},
  FilterUnit in 'FilterUnit.pas',
  NetworkEventUnit in 'NetworkEventUnit.pas' {NetworkEventForm};

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TForm1, Form1);
  Application.CreateForm(TNetworkEventForm, NetworkEventForm);
  Application.Run;
end.
