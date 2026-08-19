/**
 * AccountPopover.test.tsx — component + interaction tests (P335).
 * React Testing Library + user-event. wagmi is mocked (standard practice for
 * component tests); the editable-name flow is tested against the real
 * user_profile store (localStorage).
 */
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AccountPopover } from "@/components/AccountPopover";
import { USER_NAME_STORAGE_KEY } from "@/lib/user_profile";

const disconnectMock = jest.fn();

jest.mock("wagmi", () => ({
  useAccount: () => ({ address: "0xDA5a3D21D7EC1012965548E3443ae25c4b9D56A7", isConnected: true }),
  useDisconnect: () => ({ disconnect: disconnectMock }),
}));

jest.mock("next/navigation", () => ({
  useRouter: () => ({ push: jest.fn() }),
}));

jest.mock("@/lib/diagnostics", () => ({
  reportDiagnostic: jest.fn(),
}));

describe("AccountPopover", () => {
  beforeEach(() => {
    window.localStorage.clear();
    disconnectMock.mockClear();
  });

  it("renders the account trigger with avatar initials", () => {
    render(<AccountPopover />);
    expect(screen.getByRole("button", { name: "Open account menu" })).toBeInTheDocument();
  });

  it("opens the menu with all Phase 17 items", async () => {
    const user = userEvent.setup();
    render(<AccountPopover />);
    await user.click(screen.getByRole("button", { name: "Open account menu" }));

    expect(await screen.findByText("Upgrade Plan")).toBeInTheDocument();
    expect(screen.getByText("Personalization")).toBeInTheDocument();
    expect(screen.getByText("Profile")).toBeInTheDocument();
    expect(screen.getByText("Settings")).toBeInTheDocument();
    expect(screen.getByText("Help")).toBeInTheDocument();
    expect(screen.getByText("Disconnect Wallet")).toBeInTheDocument();
  });

  it("disconnects the wallet when Disconnect Wallet is clicked", async () => {
    const user = userEvent.setup();
    render(<AccountPopover />);
    await user.click(screen.getByRole("button", { name: "Open account menu" }));
    await user.click(await screen.findByText("Disconnect Wallet"));
    expect(disconnectMock).toHaveBeenCalledTimes(1);
  });

  it("saves an edited name to localStorage", async () => {
    const user = userEvent.setup();
    render(<AccountPopover />);
    await user.click(screen.getByRole("button", { name: "Open account menu" }));

    await user.click(screen.getByRole("button", { name: "Edit name" }));
    const input = screen.getByLabelText("Display name");
    await user.clear(input);
    await user.type(input, "Jane Dev");
    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(window.localStorage.getItem(USER_NAME_STORAGE_KEY)).toBe("Jane Dev");
    expect(await screen.findByText("Jane Dev")).toBeInTheDocument();
  });

  it("cancels an edit without persisting", async () => {
    const user = userEvent.setup();
    render(<AccountPopover />);
    await user.click(screen.getByRole("button", { name: "Open account menu" }));

    await user.click(screen.getByRole("button", { name: "Edit name" }));
    const input = screen.getByLabelText("Display name");
    await user.clear(input);
    await user.type(input, "Never Saved");
    await user.click(screen.getByRole("button", { name: "Cancel" }));

    expect(window.localStorage.getItem(USER_NAME_STORAGE_KEY)).toBeNull();
  });
});
