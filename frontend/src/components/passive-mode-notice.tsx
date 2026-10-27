import { Link } from "@tanstack/react-router";
import { Info } from "lucide-react";

import { Alert, AlertDescription } from "@/components/ui/alert";

/** Shown on scan detail pages when the scan ran in passive mode, so an
 * empty APIs / JavaScript / URLs view reads as a mode limitation rather
 * than a clean bill of health. */
export function PassiveModeNotice() {
  return (
    <Alert className="border-primary/30 bg-primary/5">
      <Info className="h-4 w-4 text-primary" />
      <AlertDescription className="text-xs">
        Passive mode does not collect JavaScript or API data.{" "}
        <Link to="/new-scan" className="font-semibold text-primary underline underline-offset-2">
          Run a Web Surface scan
        </Link>{" "}
        for client-side attack surface.
      </AlertDescription>
    </Alert>
  );
}
