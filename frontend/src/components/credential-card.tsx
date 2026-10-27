import { useEffect, useMemo, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ExternalLink, Info, KeyRound, Loader2, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { credentialsApi } from "@/api/credentials";
import type { ProviderCredential } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError } from "@/lib/api-client";

function StatusBadge({ provider }: { provider: ProviderCredential }) {
  // A saved key is not proof the vendor accepts it: only a scan confirms
  // that, so this stays neutral instead of borrowing the "working" green.
  if (provider.user_configured) {
    return (
      <Badge variant="outline" className="gap-1 border-primary/40 bg-primary/10 text-primary">
        <KeyRound className="h-3 w-3" /> Key saved
      </Badge>
    );
  }
  if (provider.configured) {
    return (
      <Badge variant="outline" className="gap-1 text-muted-foreground">
        <Info className="h-3 w-3" /> From environment
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className="text-muted-foreground">
      {provider.optional ? "Optional" : "Not set"}
    </Badge>
  );
}

export function CredentialCard({ provider }: { provider: ProviderCredential }) {
  const queryClient = useQueryClient();
  // Local editable values for each field; secret fields start empty (we never
  // receive the stored value back - only a masked hint).
  const initial = useMemo(
    () => Object.fromEntries(provider.fields.map((f) => [f.key, ""])),
    [provider.fields],
  );
  const [values, setValues] = useState<Record<string, string>>(initial);

  useEffect(() => {
    setValues(initial);
  }, [initial]);

  const save = useMutation({
    mutationFn: (fields: Record<string, string>) => credentialsApi.set(provider.provider_id, fields),
    onSuccess: (data) => {
      queryClient.setQueryData(["credentials"], data);
      toast.success(`${provider.name} updated`);
      setValues(initial);
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.message : `Could not update ${provider.name}`),
  });

  const remove = useMutation({
    mutationFn: () => credentialsApi.remove(provider.provider_id),
    onSuccess: (data) => {
      queryClient.setQueryData(["credentials"], data);
      toast.success(`${provider.name} key removed`);
      setValues(initial);
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.message : `Could not remove ${provider.name}`),
  });

  function onSave(e: React.FormEvent) {
    e.preventDefault();
    // Only send fields the user actually typed into; empty fields are left
    // untouched rather than clearing existing values.
    const changed = Object.fromEntries(
      Object.entries(values).filter(([, v]) => v.trim() !== ""),
    );
    if (Object.keys(changed).length === 0) {
      toast.info("Enter a value to save.");
      return;
    }
    save.mutate(changed);
  }

  const busy = save.isPending || remove.isPending;

  return (
    <form
      onSubmit={onSave}
      className="flex flex-col gap-3 rounded-xl border border-border/70 bg-card p-4 shadow-sm transition-shadow duration-200 hover:shadow"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="text-sm font-semibold text-foreground">{provider.name}</span>
          <StatusBadge provider={provider} />
        </div>
        {provider.signup_url && (
          <a
            href={provider.signup_url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-primary"
          >
            Get a key <ExternalLink className="h-3 w-3" />
          </a>
        )}
      </div>

      {provider.free_tier && (
        <p className="text-xs text-muted-foreground">{provider.free_tier}</p>
      )}

      <div className="grid gap-3 sm:grid-cols-2">
        {provider.fields.map((field) => (
          <div key={field.key} className="flex flex-col gap-1.5">
            <Label htmlFor={`${provider.provider_id}-${field.key}`} className="text-xs">
              {field.label}
              {field.configured && field.hint && (
                <span className="ml-2 font-mono text-[10px] text-muted-foreground">
                  {field.hint}
                  {field.from_environment ? " (env)" : ""}
                </span>
              )}
            </Label>
            <Input
              id={`${provider.provider_id}-${field.key}`}
              type={field.secret ? "password" : "text"}
              autoComplete="off"
              spellCheck={false}
              placeholder={
                field.configured ? "Enter a new value to replace" : `Enter ${field.label.toLowerCase()}`
              }
              value={values[field.key] ?? ""}
              onChange={(e) => setValues((v) => ({ ...v, [field.key]: e.target.value }))}
            />
          </div>
        ))}
      </div>

      <div className="flex items-center gap-2">
        <Button type="submit" size="sm" disabled={busy}>
          {save.isPending && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
          Save
        </Button>
        {provider.user_configured && (
          <Button
            type="button"
            size="sm"
            variant="ghost"
            className="text-destructive hover:text-destructive"
            disabled={busy}
            onClick={() => remove.mutate()}
          >
            {remove.isPending ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Trash2 className="h-3.5 w-3.5" />
            )}
            Remove
          </Button>
        )}
      </div>
    </form>
  );
}
