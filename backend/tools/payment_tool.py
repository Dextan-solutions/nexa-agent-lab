from __future__ import annotations

from typing import Any, Mapping

from tools.banking_client import http_disburse_loan


class PaymentTool:
    """Loan disbursement bridge (Leo). At LOW the API performs no approval checks."""

    def disburse(
        self,
        *,
        application_id: str,
        disbursement_account: str,
        amount: float,
        narration: str | None = None,
    ) -> Mapping[str, Any]:
        return http_disburse_loan(
            application_id=application_id,
            disbursement_account=disbursement_account,
            amount=amount,
            narration=narration,
        )
