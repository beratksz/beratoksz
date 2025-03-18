using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace beratoksz.Migrations
{
    /// <inheritdoc />
    public partial class AddSessionTrackingToActivityLogs : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsActiveSession",
                table: "ActivityLogs",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<DateTime>(
                name: "SessionEnd",
                table: "ActivityLogs",
                type: "datetime2",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "SessionId",
                table: "ActivityLogs",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<DateTime>(
                name: "SessionStart",
                table: "ActivityLogs",
                type: "datetime2",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsActiveSession",
                table: "ActivityLogs");

            migrationBuilder.DropColumn(
                name: "SessionEnd",
                table: "ActivityLogs");

            migrationBuilder.DropColumn(
                name: "SessionId",
                table: "ActivityLogs");

            migrationBuilder.DropColumn(
                name: "SessionStart",
                table: "ActivityLogs");
        }
    }
}
